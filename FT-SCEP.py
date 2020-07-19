from googleapiclient.http import MediaIoBaseUpload
from googleapiclient.discovery import build
from base64 import urlsafe_b64encode
from argparse import ArgumentParser
from os import stat, remove
from os.path import exists
from hashlib import md5
from io import BytesIO
import time
import requests
import json
from helpers import *
from tqdm import tqdm

parse = ArgumentParser(
    description="Generates a shop compatible with Tinfoil using a configuration file."
)
parse.add_argument("config", help="The config file.")
parse.add_argument(
    "--cache-path",
    type=str,
    default="titles.db.json",
    help="File path for the TitleDB cache.",
)
parse.add_argument(
    "--cache-ttl",
    type=int,
    default=28800,
    help="Time to live in seconds of the TitleDB cache. ",
)
parse.add_argument(
    "-c",
    nargs="?",
    const="",
    type=str,
    help="Uploads the shops to Google Drive, creating new files, and saves the File IDs to your configuration file. Takes in an optional folder to create the files in. Defaults to root of My Drive.",
)

args = parse.parse_args()

config = json.load(open(args.config, "r"))

if exists(args.cache_path):
    diff = time.time() - stat(args.cache_path).st_ctime
    if diff > args.cache_ttl:
        remove(args.cache_path)
    else:
        print("Loading TitleDB from {}.".format(args.cache_path))
        titledb = json.load(open(args.cache_path, "r"))

if not exists(args.cache_path):
    print("Downloading TitleDB")
    if config.get("retail_list"):
        requests.get(config["retail_list"])
    titledb = requests.get(config["titledb"]).json()
    with open(args.cache_path, "w+") as f:
        json.dump(titledb, f)
        print("Saved TitleDB to {}.".format(args.cache_path))

print("Starting Drive service.")
drive = build(
    "drive", "v3", credentials=get_creds(config["credentials"], config["token"])
)

print("Getting all files and sharing new ones. (This may take a while.)")

def lookforfiles():
    all_files = []
    for folder_id in config["mirrors"]:
        get_all_files_in_folder(drive, folder_id, all_files, recursion=True)
    return all_files

def run_shared(all_files):
    files_to_share = []
    for s in all_files:
        for k in s:
            share_filet = False
            if not s[k]["shared"]:
                share_filet = True
            if share_filet == True:
                files_to_share.append(k)
    return files_to_share

def share_file(file_id_to_share):
        drive.permissions().create(fileId=file_id_to_share, supportsAllDrives=True, body={
            "role": "reader",
            "type": "anyone"
        })

def sharefiles(runtin: int):
    all_files = lookforfiles()
    files_to_share = run_shared(all_files)
    if len(files_to_share) > 0:
        if len(files_to_share) < 300:
            for i in tqdm(range(len(files_to_share)), desc="Single File Share Progress"):
                share_file(files_to_share[i])
            return all_files
        if runtin < 100:
            runtin = 50
        print('Sharing a total of {} files.'.format(len(files_to_share)))
        n = runtin
        batches = [files_to_share[i:i + n] for i in range(0, len(files_to_share), n)]
        with tqdm(total=len(files_to_share)) as pbar:
            for i in batches:
                batch = drive.new_batch_http_request()
                for j in i:
                    batch.add(drive.permissions().create(fileId=j,body={'role':'reader','type':'anyone'},supportsAllDrives=True))
                batch.execute()
                time.sleep(2)
                pbar.update(n)
        print('Finished sharing. Checking for files missed by batch request.')
        sharefiles(n-100)
    else:
        print('No Files to share in these folder(s)')
    return all_files

all_files = sharefiles(300)

print("Matching files.")

for i in all_files:
    for us in i:
        tid = find_title_id(i[us]["name"])
        if tid in titledb:
            #print(i[us])
            if "mirrors" not in titledb[tid]:
                titledb[tid]["mirrors"] = {}

            if i[us]["fileExtension"] not in titledb[tid]["mirrors"]:
                titledb[tid]["mirrors"][i[us]["fileExtension"]] = []

            titledb[tid]["mirrors"][i[us]["fileExtension"]].append(generate_entry(us,i[us]))

        elif tid not in titledb:
            print("Not found in titledb: %s" % tid)

# Remove entries from the database that do not have any mirrors
for i in list(titledb.items()):
    if "mirrors" not in i[1]:
        titledb.pop(i[0])

titledb = titledb.values()

print("Splitting Database")

first_base = []
first_updates = []
first_dlc = []
regular_base = []
regular_updates = []
regular_dlc = []
lps = []

for i in titledb:
    if i["id"].endswith("000"):
        if i.get("publisher") == "Nintendo":
            #print(i["name"])
            first_base.append(i)
        else:
            regular_base.append(i)

first_ids = [i["id"][:-4] for i in first_base]

for i in titledb:
    if i["id"].endswith("000"):
        continue
    if (
        "language pack" in "{}".format(i).lower()
        or "audio pack" in "{}".format(i).lower()
    ):
        lps.append(i)
    elif i["id"][:-4] in first_ids:
        if i["id"].endswith("800"):
            first_updates.append(i)
        else:
            first_dlc.append(i)
    else:
        if i["id"].endswith("800"):
            regular_updates.append(i)
        else:
            regular_dlc.append(i)

print("Generating shops.")

first_base_shop = generate_shop(first_base)
first_updates_shop = generate_shop(first_updates)
first_dlc_shop = generate_shop(first_dlc)
regular_base_shop = generate_shop(regular_base)
regular_updates_shop = generate_shop(regular_updates)
regular_dlc_shop = generate_shop(regular_dlc)
lps_shop = generate_shop(lps)

print(
    "\nTotal File Count: {}\n"
    "First Party\n"
    "  Base: {}\n"
    "  Updates: {}\n"
    "  DLC: {}\n\n"
    "Regular\n"
    "  Base: {}\n"
    "  Updates: {}\n"
    "  DLC: {}\n\n"
    "Language Packs: {}\n".format(
        len(all_files),
        len(first_base_shop),
        len(first_updates_shop),
        len(first_dlc_shop),
        len(regular_base_shop),
        len(regular_updates_shop),
        len(regular_dlc_shop),
        len(lps_shop),
    )
)

shops = [
    {"0": [], "1": lps_shop},
    {
        "0": [],
        "1": first_base_shop,
        "2": regular_base_shop,
        "3": first_base_shop + regular_base_shop,
    },
    {
        "0": [],
        "1": first_updates_shop,
        "2": regular_updates_shop,
        "3": first_updates_shop + regular_updates_shop,
    },
    {
        "0": [],
        "1": first_dlc_shop,
        "2": regular_dlc_shop,
        "3": first_dlc_shop + regular_dlc_shop,
    },
]

for i in range(len(config["shop_configurations"])):
    encryption_key = config.get("encryption_key")
    vm_file = config.get("vm_file")
    shop_config = config["shop_configurations"][i]
    shop = dict(files=[])
    if shop_config.get("shop_contents"):
        shop = {**shop, **shop_config["shop_contents"]}

    if shop_config.get("includes"):
        includes = "{0:04d}".format(int(str(shop_config["includes"])))
        try:
            for j in range(4):
                shop["files"] += shops[j][includes[j]]
        except (KeyError, IndexError):
            raise ValueError("{} is not a valid includes value.".format(includes))

    shop_bytes = shop_json = json.dumps(shop).encode()
    shop_tinfoil = None
    if "encryption_key" in shop_config:
        encryption_key = shop_config.get("encryption_key")
    if "vm_file" in shop_config:
        vm_file = shop_config.get("vm_file")

    if encryption_key:
        shop_bytes = shop_tinfoil = encrypt(shop_bytes, encryption_key, vm_file)

    name = "Unnamed"
    save_tinfoil = None
    save_json = None
    save_cloud = None

    if "name" in shop_config:
        name = shop_config["name"]

    print("{}\n  Includes: {}".format(name, shop_config.get("includes")))

    if "json_path" in shop_config:
        print(
            "  JSON:\n    Location: {}\n    MD5: {}".format(
                shop_config["json_path"], md5(shop_json).hexdigest()
            )
        )
        with open(shop_config["json_path"], "wb+") as f:
            f.write(shop_json)

    if "tinfoil_path" in shop_config and shop_tinfoil:
        print(
            "  Tinfoil:\n    Location: {}\n    MD5: {}".format(
                shop_config["tinfoil_path"], md5(shop_tinfoil).hexdigest()
            )
        )
        with open(shop_config["tinfoil_path"], "wb+") as f:
            f.write(shop_tinfoil)

    if "file_id" in shop_config or args.c is not None:
        mimetype = "application/json"
        if shop_tinfoil:
            mimetype = "application/tinfoil"

        media = MediaIoBaseUpload(BytesIO(shop_bytes), mimetype=mimetype)
        if args.c is not None:
            body = {
                "name": "index.json",
                "mimeType": mimetype,
                "contentHints": {
                    "thumbnail": {
                        "image": urlsafe_b64encode(
                            open("tinfoil.png", "rb").read()
                        ).decode("utf8"),
                        "mimeType": "image/png",
                    }
                },
            }

            if shop_tinfoil:
                body["name"] = "index.tfl"

            if args.c != "":
                body["parents"] = [args.c]

            ur = (
                drive.files()
                .create(media_body=media, supportsAllDrives=True, body=body)
                .execute()
            )
            drive.permissions().create(
                fileId=ur["id"],
                supportsAllDrives=True,
                body={"role": "reader", "type": "anyone"},
            ).execute()
            config["shop_configurations"][i]["file_id"] = ur["id"]
        else:
            ur = (
                drive.files()
                .update(
                    fileId=shop_config["file_id"],
                    media_body=media,
                    supportsAllDrives=True,
                )
                .execute()
            )
        print(
            "  Google Drive: \n    Name: {}\n    ID: {}\n    MD5: {}".format(
                ur["name"], ur["id"], md5(shop_bytes).hexdigest()
            )
        )

if args.c is not None:
    with open(args.config, "w+") as f:
        json.dump(config, f, indent=2)
    print("\nSaved to {}".format(args.config))

print("\nDone.")
