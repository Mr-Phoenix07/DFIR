#!/usr/bin/env python3
"""mk_browser_profiles.py - write alice's Edge and Firefox profiles from WS-ALICE for browser-forensics labs.

Usage: python3 mk_browser_profiles.py OUTDIR

OUTDIR becomes the root of WS-ALICE's C:\\ drive (as in mk_win_triage_lab.py). It gets:

  Users/alice/AppData/Local/Microsoft/Edge/User Data/
      Local State                    profile list and the (DPAPI-protected) cookie key
      Default/History                urls, visits, keyword_search_terms, downloads, downloads_url_chains
      Default/Network/Cookies        cookies (values encrypted, as on Windows: placeholder bytes)
      Default/Web Data               autofill (and keywords: the search engines)
      Default/Preferences            JSON: download folder, session start/exit log
      Default/Bookmarks              JSON: the Favorites bar
  Users/alice/AppData/Roaming/Mozilla/Firefox/
      profiles.ini, installs.ini     which profile is used
      Profiles/q7w1k2zd.default-release/
          places.sqlite              moz_places, moz_historyvisits, moz_annos (downloads),
                                     moz_places_metadata (page interactions), moz_origins
          cookies.sqlite             moz_cookies
          formhistory.sqlite         moz_formhistory: values typed into web forms
          prefs.js, times.json       version and profile creation time

The SQLite tables use the browsers' real definitions: Edge's are copied from a Chromium 141 profile
(History schema version 70, Cookies 24, Web Data 143; Web Data keeps only its autofill, keywords and
meta tables), Firefox's from the Firefox 155 source (places schema 87, cookies 17, form history 5;
indexes and triggers are left out and moz_places.url_hash is 0). Firefox's databases are in WAL
mode, as Firefox writes them. The rows are made up and follow the WS-ALICE story of earlier days.

Times are UTC. Chromium stores microseconds since 1601 (WebKit time) in its databases; Firefox
stores microseconds since 1970 (PRTime) in places.sqlite, but milliseconds or seconds in some other
columns: those are noted below. File modification times are set to fixed story times; the SQLite
files themselves can differ by a few header bytes between SQLite versions, so don't compare their
hashes across machines. Standard library only.
"""
import base64
import calendar
import datetime
import hashlib
import json
import os
import sqlite3
import sys

EPOCH_1601 = datetime.datetime(1601, 1, 1)
EPOCH_1970 = datetime.datetime(1970, 1, 1)


def dt(text):
    return datetime.datetime.fromisoformat(text)


def webkit(text):
    """Chromium/Edge time: microseconds since 1601-01-01 UTC."""
    d = dt(text) - EPOCH_1601
    return (d.days * 86400 + d.seconds) * 1000000 + d.microseconds


def prtime(text):
    """Firefox PRTime: microseconds since 1970-01-01 UTC."""
    d = dt(text) - EPOCH_1970
    return (d.days * 86400 + d.seconds) * 1000000 + d.microseconds


def unix(text):
    return prtime(text) // 1000000


def unix_ms(text):
    return prtime(text) // 1000


def filler(label, size):
    """Deterministic stand-in bytes (for encrypted values that can't be real)."""
    out = b""
    while len(out) < size:
        out += hashlib.sha256(label.encode() + len(out).to_bytes(4, "little")).digest()
    return out[:size]


# ---------------------------------------------------------------------------------------------
# Edge (Chromium 141 schema)

HISTORY_DDL = """
CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT,url LONGVARCHAR,title LONGVARCHAR,visit_count INTEGER DEFAULT 0 NOT NULL,typed_count INTEGER DEFAULT 0 NOT NULL,last_visit_time INTEGER NOT NULL,hidden INTEGER DEFAULT 0 NOT NULL);
CREATE TABLE visits(id INTEGER PRIMARY KEY AUTOINCREMENT,url INTEGER NOT NULL,visit_time INTEGER NOT NULL,from_visit INTEGER,external_referrer_url TEXT,transition INTEGER DEFAULT 0 NOT NULL,segment_id INTEGER,visit_duration INTEGER DEFAULT 0 NOT NULL,incremented_omnibox_typed_score BOOLEAN DEFAULT FALSE NOT NULL,opener_visit INTEGER,originator_cache_guid TEXT,originator_visit_id INTEGER,originator_from_visit INTEGER,originator_opener_visit INTEGER,is_known_to_sync BOOLEAN DEFAULT FALSE NOT NULL,consider_for_ntp_most_visited BOOLEAN DEFAULT FALSE NOT NULL,visited_link_id INTEGER DEFAULT 0 NOT NULL,app_id TEXT);
CREATE TABLE visit_source(id INTEGER PRIMARY KEY,source INTEGER NOT NULL);
CREATE INDEX visits_url_index ON visits (url);
CREATE INDEX visits_from_index ON visits (from_visit);
CREATE INDEX visits_time_index ON visits (visit_time);
CREATE INDEX visits_originator_id_index ON visits (originator_visit_id);
CREATE TABLE keyword_search_terms (keyword_id INTEGER NOT NULL,url_id INTEGER NOT NULL,term LONGVARCHAR NOT NULL,normalized_term LONGVARCHAR NOT NULL);
CREATE INDEX keyword_search_terms_index1 ON keyword_search_terms (keyword_id, normalized_term);
CREATE INDEX keyword_search_terms_index2 ON keyword_search_terms (url_id);
CREATE INDEX keyword_search_terms_index3 ON keyword_search_terms (term);
CREATE TABLE downloads (id INTEGER PRIMARY KEY,guid VARCHAR NOT NULL,current_path LONGVARCHAR NOT NULL,target_path LONGVARCHAR NOT NULL,start_time INTEGER NOT NULL,received_bytes INTEGER NOT NULL,total_bytes INTEGER NOT NULL,state INTEGER NOT NULL,danger_type INTEGER NOT NULL,interrupt_reason INTEGER NOT NULL,hash BLOB NOT NULL,end_time INTEGER NOT NULL,opened INTEGER NOT NULL,last_access_time INTEGER NOT NULL,transient INTEGER NOT NULL,referrer VARCHAR NOT NULL,site_url VARCHAR NOT NULL,embedder_download_data VARCHAR NOT NULL,tab_url VARCHAR NOT NULL,tab_referrer_url VARCHAR NOT NULL,http_method VARCHAR NOT NULL,by_ext_id VARCHAR NOT NULL,by_ext_name VARCHAR NOT NULL,by_web_app_id VARCHAR NOT NULL,etag VARCHAR NOT NULL,last_modified VARCHAR NOT NULL,mime_type VARCHAR(255) NOT NULL,original_mime_type VARCHAR(255) NOT NULL);
CREATE TABLE downloads_url_chains (id INTEGER NOT NULL,chain_index INTEGER NOT NULL,url LONGVARCHAR NOT NULL, PRIMARY KEY (id, chain_index) );
CREATE TABLE downloads_slices (download_id INTEGER NOT NULL,offset INTEGER NOT NULL,received_bytes INTEGER NOT NULL,finished INTEGER NOT NULL DEFAULT 0,PRIMARY KEY (download_id, offset) );
CREATE TABLE segments (id INTEGER PRIMARY KEY,name VARCHAR,url_id INTEGER NON NULL);
CREATE INDEX segments_name ON segments(name);
CREATE INDEX segments_url_id ON segments(url_id);
CREATE TABLE segment_usage (id INTEGER PRIMARY KEY,segment_id INTEGER NOT NULL,time_slot INTEGER NOT NULL,visit_count INTEGER DEFAULT 0 NOT NULL);
CREATE INDEX segment_usage_time_slot_segment_id ON segment_usage(time_slot, segment_id);
CREATE INDEX segments_usage_seg_id ON segment_usage(segment_id);
CREATE TABLE content_annotations(visit_id INTEGER PRIMARY KEY,visibility_score NUMERIC,floc_protected_score NUMERIC,categories VARCHAR,page_topics_model_version INTEGER,annotation_flags INTEGER NOT NULL,entities VARCHAR,related_searches VARCHAR,search_normalized_url VARCHAR,search_terms LONGVARCHAR,alternative_title VARCHAR,page_language VARCHAR,password_state INTEGER DEFAULT 0 NOT NULL,has_url_keyed_image BOOLEAN NOT NULL);
CREATE TABLE context_annotations(visit_id INTEGER PRIMARY KEY,context_annotation_flags INTEGER NOT NULL,duration_since_last_visit INTEGER,page_end_reason INTEGER,total_foreground_duration INTEGER,browser_type INTEGER DEFAULT 0 NOT NULL,window_id INTEGER DEFAULT -1 NOT NULL,tab_id INTEGER DEFAULT -1 NOT NULL,task_id INTEGER DEFAULT -1 NOT NULL,root_task_id INTEGER DEFAULT -1 NOT NULL,parent_task_id INTEGER DEFAULT -1 NOT NULL,response_code INTEGER DEFAULT 0 NOT NULL);
CREATE TABLE clusters(cluster_id INTEGER PRIMARY KEY AUTOINCREMENT,should_show_on_prominent_ui_surfaces BOOLEAN NOT NULL,label VARCHAR NOT NULL,raw_label VARCHAR NOT NULL,triggerability_calculated BOOLEAN NOT NULL,originator_cache_guid TEXT NOT NULL,originator_cluster_id INTEGER NOT NULL);
CREATE TABLE clusters_and_visits(cluster_id INTEGER NOT NULL,visit_id INTEGER NOT NULL,score NUMERIC DEFAULT 0 NOT NULL,engagement_score NUMERIC DEFAULT 0 NOT NULL,url_for_deduping LONGVARCHAR NOT NULL,normalized_url LONGVARCHAR NOT NULL,url_for_display LONGVARCHAR NOT NULL,interaction_state INTEGER DEFAULT 0 NOT NULL,PRIMARY KEY(cluster_id,visit_id))WITHOUT ROWID;
CREATE INDEX clusters_for_visit ON clusters_and_visits(visit_id);
CREATE TABLE cluster_keywords(cluster_id INTEGER NOT NULL,keyword VARCHAR NOT NULL,type INTEGER NOT NULL,score NUMERIC NOT NULL,collections VARCHAR NOT NULL);
CREATE INDEX cluster_keywords_cluster_id_index ON cluster_keywords(cluster_id);
CREATE TABLE cluster_visit_duplicates(visit_id INTEGER NOT NULL,duplicate_visit_id INTEGER NOT NULL,PRIMARY KEY(visit_id,duplicate_visit_id))WITHOUT ROWID;
CREATE TABLE visited_links(id INTEGER PRIMARY KEY AUTOINCREMENT,link_url_id INTEGER NOT NULL,top_level_url LONGVARCHAR NOT NULL,frame_url LONGVARCHAR NOT NULL,visit_count INTEGER DEFAULT 0 NOT NULL);
CREATE INDEX visited_links_index ON visited_links (link_url_id, top_level_url, frame_url);
CREATE TABLE history_sync_metadata (storage_key INTEGER PRIMARY KEY NOT NULL, value BLOB);
CREATE INDEX urls_url_index ON urls (url);
"""

COOKIES_DDL = """
CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
CREATE TABLE cookies(creation_utc INTEGER NOT NULL,host_key TEXT NOT NULL,top_frame_site_key TEXT NOT NULL,name TEXT NOT NULL,value TEXT NOT NULL,encrypted_value BLOB NOT NULL,path TEXT NOT NULL,expires_utc INTEGER NOT NULL,is_secure INTEGER NOT NULL,is_httponly INTEGER NOT NULL,last_access_utc INTEGER NOT NULL,has_expires INTEGER NOT NULL,is_persistent INTEGER NOT NULL,priority INTEGER NOT NULL,samesite INTEGER NOT NULL,source_scheme INTEGER NOT NULL,source_port INTEGER NOT NULL,last_update_utc INTEGER NOT NULL,source_type INTEGER NOT NULL,has_cross_site_ancestor INTEGER NOT NULL);
CREATE UNIQUE INDEX cookies_unique_index ON cookies(host_key, top_frame_site_key, has_cross_site_ancestor, name, path, source_scheme, source_port);
"""

WEBDATA_DDL = """
CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
CREATE TABLE autofill (name VARCHAR, value VARCHAR, value_lower VARCHAR, date_created INTEGER DEFAULT 0, date_last_used INTEGER DEFAULT 0, count INTEGER DEFAULT 1, PRIMARY KEY (name, value));
CREATE INDEX autofill_name ON autofill(name);
CREATE INDEX autofill_name_value_lower ON autofill(name, value_lower);
CREATE TABLE keywords (id INTEGER PRIMARY KEY,short_name VARCHAR NOT NULL,keyword VARCHAR NOT NULL,favicon_url VARCHAR NOT NULL,url VARCHAR NOT NULL,safe_for_autoreplace INTEGER,originating_url VARCHAR,date_created INTEGER DEFAULT 0,usage_count INTEGER DEFAULT 0,input_encodings VARCHAR,suggest_url VARCHAR,prepopulate_id INTEGER DEFAULT 0,created_by_policy INTEGER DEFAULT 0,last_modified INTEGER DEFAULT 0,sync_guid VARCHAR,alternate_urls VARCHAR,image_url VARCHAR,search_url_post_params VARCHAR,suggest_url_post_params VARCHAR,image_url_post_params VARCHAR,new_tab_url VARCHAR,last_visited INTEGER DEFAULT 0, created_from_play_api INTEGER DEFAULT 0, is_active INTEGER DEFAULT 0, starter_pack_id INTEGER DEFAULT 0, enforced_by_policy INTEGER DEFAULT 0, featured_by_policy INTEGER DEFAULT 0, url_hash BLOB);
"""

# Page transition = core type (low byte) + qualifier bits. Core: 0 LINK, 1 TYPED, 2 AUTO_BOOKMARK,
# 5 GENERATED (a search typed in the address bar), 7 FORM_SUBMIT. Qualifiers: 0x02000000
# FROM_ADDRESS_BAR, 0x10000000 CHAIN_START, 0x20000000 CHAIN_END.
LINK, TYPED, AUTO_BOOKMARK, GENERATED = 0, 1, 2, 5
FROM_ADDRESS_BAR, CHAIN = 0x02000000, 0x30000000

BING = "https://www.bing.com/search?q={}&form=ANAB01&pc=U531"
# (url_id, url, title)
EDGE_URLS = [
    (1, "https://intranet.corp.example/", "Corp Intranet - Home"),
    (2, "https://mail.corp.example/owa/", "Mail - alice@corp.example"),
    (3, BING.format("rclone+mega+config"), "rclone mega config - Search"),
    (4, "https://rclone.org/mega/", "Mega"),
    (5, BING.format("powershell+run+script+from+url+one+line"), "powershell run script from url one line - Search"),
    (6, "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression",
     "Invoke-Expression (Microsoft.PowerShell.Utility) - PowerShell | Microsoft Learn"),
]
# (visit_id, url_id, time, from_visit, transition, duration in seconds)
EDGE_VISITS = [
    (1, 1, "2026-09-28 07:59:44.204118", 0, AUTO_BOOKMARK | CHAIN, 81.7),
    (2, 2, "2026-09-28 08:01:06.511730", 0, AUTO_BOOKMARK | CHAIN, 36089.3),
    (3, 2, "2026-09-29 00:59:47.302551", 0, AUTO_BOOKMARK | CHAIN, 35.6),
    (4, 3, "2026-09-29 01:00:22.918406", 0, GENERATED | FROM_ADDRESS_BAR | CHAIN, 8.5),
    (5, 4, "2026-09-29 01:00:31.455210", 4, LINK | CHAIN, 38.2),
    (6, 5, "2026-09-29 01:01:09.700334", 0, GENERATED | FROM_ADDRESS_BAR | CHAIN, 11.4),
    (7, 6, "2026-09-29 01:01:21.163907", 6, LINK | CHAIN, 41.7),
]
EDGE_SEARCHES = [(3, "rclone mega config"), (5, "powershell run script from url one line")]

PAYLOAD_URL = "http://203.0.113.50/payload.ps1"
PAYLOAD_SIZE = 75                                        # the file of Days 10 and 16
PAYLOAD_SERVER_MTIME = "2026-09-28 23:41:09"             # the web server's Last-Modified
DL_START, DL_END = "2026-09-29 01:02:02.874516", "2026-09-29 01:02:03.126702"

EDGE_SESSIONS = [  # Preferences sessions.event_log: 0 = profile started, 2 = exit
    ("2026-09-28 07:59:31.410227", 0, None),
    ("2026-09-28 18:02:35.902114", 2, 2),
    ("2026-09-29 00:59:12.901385", 0, None),
    ("2026-09-29 01:36:44.215067", 2, 4),
]


def make_db(path, ddl, rows, meta=None, wal=False, user_version=None):
    if os.path.exists(path):
        os.remove(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    con = sqlite3.connect(path)
    if wal:
        con.execute("PRAGMA journal_mode=WAL")
    con.executescript(ddl)
    for key, value in (meta or {}).items():
        con.execute("INSERT INTO meta VALUES (?, ?)", (key, value))
    for table, table_rows in rows:
        for row in table_rows:
            con.execute(f"INSERT INTO {table} VALUES ({','.join('?' * len(row))})", row)
    if user_version is not None:
        con.execute(f"PRAGMA user_version = {user_version}")
    con.commit()
    con.close()


def edge(root):
    ud = os.path.join(root, "Users/alice/AppData/Local/Microsoft/Edge/User Data")
    prof = os.path.join(ud, "Default")
    meta = {"mmap_status": "-1", "version": "70", "last_compatible_version": "16"}

    last = {}
    for _, url_id, when, _, _, _ in EDGE_VISITS:
        last[url_id] = max(last.get(url_id, ""), when)
    counts = {u: sum(1 for v in EDGE_VISITS if v[1] == u) for u, _, _ in EDGE_URLS}
    typed = {u: sum(1 for v in EDGE_VISITS if v[1] == u and v[4] & 0xFF == TYPED) for u, _, _ in EDGE_URLS}
    urls = [(u, url, title, counts[u], typed[u], webkit(last[u]), 0) for u, url, title in EDGE_URLS]
    visits = [(vid, u, webkit(when), frm, None, tr, 0, int(dur * 1000000), 0, 0, None, 0, 0, 0, 0, 1, 0, None)
              for vid, u, when, frm, tr, dur in EDGE_VISITS]
    searches = [(3, u, term, term) for u, term in EDGE_SEARCHES]   # keyword 3 = Bing (Web Data)
    mtime_us = unix(PAYLOAD_SERVER_MTIME) * 1000000
    last_modified = dt(PAYLOAD_SERVER_MTIME).strftime("%a, %d %b %Y %H:%M:%S GMT")
    downloads = [(1, "7c1f0d9e-5a2b-4c8e-9f31-2b6a8d40e512", r"C:\Users\alice\Downloads\payload.ps1",
                  r"C:\Users\alice\Downloads\payload.ps1", webkit(DL_START), PAYLOAD_SIZE, PAYLOAD_SIZE,
                  1, 0, 0, b"", webkit(DL_END), 0, 0, 0, "", "", "", "", "", "GET", "", "", "",
                  f'"{PAYLOAD_SIZE:x}-{mtime_us:x}"', last_modified,
                  "application/octet-stream", "application/octet-stream")]
    make_db(os.path.join(prof, "History"), HISTORY_DDL,
            [("urls", urls), ("visits", visits), ("keyword_search_terms", searches),
             ("downloads", downloads), ("downloads_url_chains", [(1, 0, PAYLOAD_URL)])], meta)

    def cookie(host, name, created, accessed, expires, secure, httponly, samesite):
        enc = b"v10" + filler(f"edge-cookie-{host}-{name}", 12 + 32 + 16)   # nonce + data + tag
        return (webkit(created), host, "", name, "", enc, "/", webkit(expires), secure, httponly,
                webkit(accessed), 1, 1, 1, samesite, 2, 443, webkit(created), 1, 0)
    cookies = [
        cookie(".bing.com", "MUID", "2026-03-02 09:14:22.511020", "2026-09-29 01:01:09.912447",
               "2027-04-06 09:14:22.511020", 1, 0, 0),
        cookie("mail.corp.example", "session", "2026-09-28 08:01:07.019334", "2026-09-29 00:59:47.611208",
               "2026-10-28 08:01:07.019334", 1, 1, 1),
    ]
    make_db(os.path.join(prof, "Network/Cookies"), COOKIES_DDL, [("cookies", cookies)],
            {"mmap_status": "-1", "version": "24", "last_compatible_version": "24"})

    autofill = [
        ("username", "alice", "alice", unix("2026-03-02 09:20:05"), unix("2026-09-28 07:59:52"), 41),
        ("email", "alice@corp.example", "alice@corp.example", unix("2026-03-04 13:02:41"),
         unix("2026-09-21 15:44:10"), 6),
    ]
    keywords = [
        (2, "Google", "google.com", "https://www.google.com/favicon.ico",
         "{google:baseURL}search?q={searchTerms}", 1, "", 0, 0, "UTF-8", "", 1, 0, 0, "", "[]", "", "", "",
         "", "", 0, 0, 0, 0, 0, 0, None),
        (3, "Microsoft Bing", "bing.com", "https://www.bing.com/sa/simg/favicon-2x.ico",
         "https://www.bing.com/search?q={searchTerms}", 1, "", 0, 0, "UTF-8", "", 3, 0, 0, "", "[]", "", "",
         "", "", "", 0, 0, 1, 0, 0, 0, None),
    ]
    make_db(os.path.join(prof, "Web Data"), WEBDATA_DDL, [("autofill", autofill), ("keywords", keywords)],
            {"mmap_status": "-1", "version": "143", "last_compatible_version": "139"})

    event_log = []
    for when, kind, tabs in EDGE_SESSIONS:
        entry = {"crashed": False, "time": str(webkit(when)), "type": kind}
        if kind == 2:
            entry = {"did_schedule_command": True, "first_session_service": True, "tab_count": tabs,
                     "time": str(webkit(when)), "type": 2, "window_count": 1}
        event_log.append(entry)
    prefs = {
        "download": {"default_directory": "C:\\Users\\alice\\Downloads", "prompt_for_download": False},
        "edge": {},
        "intl": {"accept_languages": "en-US,en"},
        "profile": {"creation_time": str(webkit("2026-03-02 09:14:20.118205")), "exit_type": "Normal",
                    "last_engagement_time": str(webkit("2026-09-29 01:01:21.163907")), "name": "Profile 1"},
        "savefile": {"default_directory": "C:\\Users\\alice\\Downloads"},
        "sessions": {"event_log": event_log},
    }
    write(os.path.join(prof, "Preferences"), json.dumps(prefs, separators=(",", ":")).encode())

    def bm(node_id, name, url, added, used):
        return {"date_added": str(webkit(added)), "date_last_used": str(webkit(used)),
                "guid": f"5f0e1c2a-7b3d-4e8f-a1b2-{node_id:012d}", "id": str(node_id), "name": name,
                "type": "url", "url": url}

    def folder(node_id, name, guid, children):
        return {"children": children, "date_added": str(webkit("2026-03-02 09:14:20.204581")),
                "date_last_used": "0", "date_modified": str(webkit("2026-03-02 09:16:03.551820")) if children
                else "0", "guid": guid, "id": str(node_id), "name": name, "type": "folder"}
    bookmarks = {"roots": {
        "bookmark_bar": folder(1, "Favorites bar", "0bc5d13f-2cba-5d74-951f-3f233fe6c908", [
            bm(5, "Intranet", EDGE_URLS[0][1], "2026-03-02 09:15:41.302114", EDGE_VISITS[0][2]),
            bm(6, "Mail", EDGE_URLS[1][1], "2026-03-02 09:16:03.551820", EDGE_VISITS[2][2])]),
        "other": folder(2, "Other favorites", "82b081ec-3dd3-529c-8475-ab6c344590dd", []),
        "synced": folder(3, "Mobile favorites", "4cf2e351-0e85-532b-bb37-df045d8f8d0f", [])},
        "version": 1}
    write(os.path.join(prof, "Bookmarks"), json.dumps(bookmarks, indent=3).encode())

    dpapi_blob = b"DPAPI" + bytes.fromhex("01000000d08c9ddf0115d1118c7a00c04fc297eb") + filler("edge-key", 210)
    local_state = {
        "os_crypt": {"encrypted_key": base64.b64encode(dpapi_blob).decode()},
        "profile": {"info_cache": {"Default": {"active_time": unix("2026-09-29 01:01:21"), "name": "Profile 1",
                                               "user_name": ""}},
                    "last_used": "Default", "profiles_order": ["Default"]},
    }
    write(os.path.join(ud, "Local State"), json.dumps(local_state, separators=(",", ":")).encode())

    stamp(os.path.join(prof, "History"), "2026-09-29 01:36:44")
    stamp(os.path.join(prof, "Network/Cookies"), "2026-09-29 01:36:44")
    stamp(os.path.join(prof, "Web Data"), "2026-09-28 18:02:35")
    stamp(os.path.join(prof, "Preferences"), "2026-09-29 01:36:44")
    stamp(os.path.join(prof, "Bookmarks"), "2026-03-02 09:16:03")
    stamp(os.path.join(ud, "Local State"), "2026-09-29 01:36:44")


# ---------------------------------------------------------------------------------------------
# Firefox (Firefox 155 schema, from toolkit/components/places/nsPlacesTables.h,
# netwerk/cookie/CookiePersistentStorage.cpp and toolkit/components/satchel/FormHistory.sys.mjs)

PLACES_DDL = """
CREATE TABLE moz_origins ( id INTEGER PRIMARY KEY, prefix TEXT NOT NULL, host TEXT NOT NULL, frecency INTEGER NOT NULL, recalc_frecency INTEGER NOT NULL DEFAULT 0, alt_frecency INTEGER, recalc_alt_frecency INTEGER NOT NULL DEFAULT 0, block_until_ms INTEGER, block_pages_until_ms INTEGER, UNIQUE (host, prefix) );
CREATE TABLE moz_places ( id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, rev_host LONGVARCHAR, visit_count INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0 NOT NULL, typed INTEGER DEFAULT 0 NOT NULL, frecency INTEGER DEFAULT -1 NOT NULL, last_visit_date INTEGER , guid TEXT, foreign_count INTEGER DEFAULT 0 NOT NULL, url_hash INTEGER DEFAULT 0 NOT NULL , description TEXT, preview_image_url TEXT, site_name TEXT, origin_id INTEGER REFERENCES moz_origins(id), recalc_frecency INTEGER NOT NULL DEFAULT 0, alt_frecency INTEGER, recalc_alt_frecency INTEGER NOT NULL DEFAULT 0);
CREATE TABLE moz_historyvisits ( id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER, session INTEGER, source INTEGER DEFAULT 0 NOT NULL, triggeringPlaceId INTEGER);
CREATE TABLE moz_inputhistory ( place_id INTEGER NOT NULL, input LONGVARCHAR NOT NULL, use_count INTEGER, PRIMARY KEY (place_id, input));
CREATE TABLE moz_bookmarks ( id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER DEFAULT NULL, parent INTEGER, position INTEGER, title LONGVARCHAR, keyword_id INTEGER, folder_type TEXT, dateAdded INTEGER, lastModified INTEGER, guid TEXT, syncStatus INTEGER NOT NULL DEFAULT 0, syncChangeCounter INTEGER NOT NULL DEFAULT 1);
CREATE TABLE moz_bookmarks_deleted ( guid TEXT PRIMARY KEY, dateRemoved INTEGER NOT NULL DEFAULT 0);
CREATE TABLE moz_keywords ( id INTEGER PRIMARY KEY AUTOINCREMENT, keyword TEXT UNIQUE, place_id INTEGER, post_data TEXT);
CREATE TABLE moz_anno_attributes ( id INTEGER PRIMARY KEY, name VARCHAR(32) UNIQUE NOT NULL);
CREATE TABLE moz_annos ( id INTEGER PRIMARY KEY, place_id INTEGER NOT NULL, anno_attribute_id INTEGER, content LONGVARCHAR, flags INTEGER DEFAULT 0, expiration INTEGER DEFAULT 0, type INTEGER DEFAULT 0, dateAdded INTEGER DEFAULT 0, lastModified INTEGER DEFAULT 0);
CREATE TABLE moz_items_annos ( id INTEGER PRIMARY KEY, item_id INTEGER NOT NULL, anno_attribute_id INTEGER, content LONGVARCHAR, flags INTEGER DEFAULT 0, expiration INTEGER DEFAULT 0, type INTEGER DEFAULT 0, dateAdded INTEGER DEFAULT 0, lastModified INTEGER DEFAULT 0);
CREATE TABLE moz_meta (key TEXT PRIMARY KEY, value NOT NULL) WITHOUT ROWID;
CREATE TABLE moz_places_metadata_search_queries ( id INTEGER PRIMARY KEY, terms TEXT NOT NULL UNIQUE );
CREATE TABLE moz_places_metadata (id INTEGER PRIMARY KEY, place_id INTEGER NOT NULL, referrer_place_id INTEGER, created_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0, total_view_time INTEGER NOT NULL DEFAULT 0, typing_time INTEGER NOT NULL DEFAULT 0, key_presses INTEGER NOT NULL DEFAULT 0, scrolling_time INTEGER NOT NULL DEFAULT 0, scrolling_distance INTEGER NOT NULL DEFAULT 0, document_type INTEGER NOT NULL DEFAULT 0, search_query_id INTEGER, FOREIGN KEY (place_id) REFERENCES moz_places(id) ON DELETE CASCADE, FOREIGN KEY (referrer_place_id) REFERENCES moz_places(id) ON DELETE CASCADE, FOREIGN KEY(search_query_id) REFERENCES moz_places_metadata_search_queries(id) ON DELETE CASCADE CHECK(place_id != referrer_place_id) );
CREATE TABLE moz_previews_tombstones ( hash TEXT PRIMARY KEY ) WITHOUT ROWID;
CREATE TABLE moz_places_extra ( place_id INTEGER PRIMARY KEY NOT NULL, sync_json TEXT, FOREIGN KEY (place_id) REFERENCES moz_places(id) ON DELETE CASCADE );
CREATE TABLE moz_historyvisits_extra ( visit_id INTEGER PRIMARY KEY NOT NULL, sync_json TEXT, FOREIGN KEY (visit_id) REFERENCES moz_historyvisits(id) ON DELETE CASCADE);
"""

FF_COOKIES_DDL = """
CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, originAttributes TEXT NOT NULL DEFAULT '', name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, inBrowserElement INTEGER DEFAULT 0, sameSite INTEGER DEFAULT 0, schemeMap INTEGER DEFAULT 0, isPartitionedAttributeSet INTEGER DEFAULT 0, updateTime INTEGER, CONSTRAINT moz_uniqueid UNIQUE (name, host, path, originAttributes));
"""

FORMHISTORY_DDL = """
CREATE TABLE moz_formhistory (id INTEGER PRIMARY KEY, fieldname TEXT NOT NULL, value TEXT NOT NULL, timesUsed INTEGER, firstUsed INTEGER, lastUsed INTEGER, guid TEXT);
CREATE TABLE moz_deleted_formhistory (id INTEGER PRIMARY KEY, timeDeleted INTEGER, guid TEXT);
CREATE TABLE moz_sources (id INTEGER PRIMARY KEY, source TEXT NOT NULL);
CREATE TABLE moz_history_to_sources (history_id INTEGER, source_id INTEGER, PRIMARY KEY (history_id, source_id), FOREIGN KEY (history_id) REFERENCES moz_formhistory(id) ON DELETE CASCADE, FOREIGN KEY (source_id) REFERENCES moz_sources(id) ON DELETE CASCADE);
"""

FF_PROFILE = "q7w1k2zd.default-release"
FF_CREATED = "2026-06-11 12:40:05.381"
FF_DL_ZIP = "https://downloads.rclone.org/v1.68.2/rclone-v1.68.2-windows-amd64.zip"
# moz_historyvisits.visit_type: 1 LINK, 2 TYPED, 7 DOWNLOAD. source: 0 organic, 3 search results page.
# (place_id, url, title, origin_id, time, visit_type, from_visit, source)
FF_VISITS = [
    (1, "https://www.bing.com/search?q=copy+whole+folder+to+mega+without+the+app&pc=MOZI&form=MOZLBR",
     "copy whole folder to mega without the app - Search", 1, "2026-09-28 10:08:55.210331", 1, 0, 3),
    (2, "https://rclone.org/mega/", "Mega", 2, "2026-09-28 10:09:21.877604", 1, 1, 0),
    (3, "https://mega.nz/register", "MEGA", 3, "2026-09-28 10:10:12.519870", 1, 2, 0),
    (4, "https://rclone.org/downloads/", "Rclone downloads", 2, "2026-09-28 10:11:02.403118", 1, 2, 0),
    (5, FF_DL_ZIP, None, 4, "2026-09-28 10:11:40.118552", 7, 4, 0),
    (6, "https://downloads.example.net/", "Index of /", 5, "2026-09-28 10:12:47.660291", 2, 0, 0),
]
FF_ORIGINS = [(1, "https://", "www.bing.com"), (2, "https://", "rclone.org"), (3, "https://", "mega.nz"),
              (4, "https://", "downloads.rclone.org"), (5, "https://", "downloads.example.net")]
# Page interactions (moz_places_metadata): times in ms since 1970, durations in ms.
# (place_id, referrer, start, end, view_ms, typing_ms, key_presses, scroll_ms, scroll_px)
FF_INTERACTIONS = [
    (2, 1, "2026-09-28 10:09:21.912", "2026-09-28 10:11:02.381", 97140, 0, 0, 20550, 5412),
    (3, 2, "2026-09-28 10:10:12.560", "2026-09-28 10:10:59.807", 46830, 15820, 61, 1210, 380),
    (6, None, "2026-09-28 10:12:47.702", "2026-09-28 10:13:39.155", 51200, 0, 0, 0, 0),
]


def guid12(label):
    return base64.urlsafe_b64encode(hashlib.sha256(label.encode()).digest())[:12].decode()


def firefox(root):
    base = os.path.join(root, "Users/alice/AppData/Roaming/Mozilla/Firefox")
    prof = os.path.join(base, "Profiles", FF_PROFILE)

    origins = [(i, p, h, 100, 0, None, 0, None, None) for i, p, h in FF_ORIGINS]
    places = []
    for pid, url, title, origin, when, vtype, _, _ in FF_VISITS:
        host = url.split("/")[2]
        places.append((pid, url, title, host[::-1] + ".", 1, 0, 1 if vtype == 2 else 0, 100, prtime(when),
                       guid12(url), 0, 0, None, None, None, origin, 0, None, 0))
    visits = [(pid, frm, pid, prtime(when), vtype, 0, src, None)
              for pid, _, _, _, when, vtype, frm, src in FF_VISITS]
    dl_start, dl_end = "2026-09-28 10:11:40.402771", "2026-09-28 10:11:52.613"
    annos = [
        (1, 5, 1, "file:///C:/Users/alice/Downloads/rclone-v1.68.2-windows-amd64.zip", 0, 4, 3,
         prtime(dl_start), prtime(dl_start)),
        # state 2 = failed (DownloadHistory.sys.mjs); endTime in ms since 1970
        (2, 5, 2, json.dumps({"state": 2, "deleted": False, "endTime": unix_ms(dl_end)}, separators=(",", ":")),
         0, 4, 3, prtime(dl_end), prtime(dl_end)),
    ]
    interactions = [(i + 1, pid, ref, unix_ms(start), unix_ms(end), view, typing, keys, s_ms, s_px, 0, None)
                    for i, (pid, ref, start, end, view, typing, keys, s_ms, s_px) in enumerate(FF_INTERACTIONS)]
    make_db(os.path.join(prof, "places.sqlite"), PLACES_DDL,
            [("moz_origins", origins), ("moz_places", places), ("moz_historyvisits", visits),
             ("moz_anno_attributes", [(1, "downloads/destinationFileURI"), (2, "downloads/metaData")]),
             ("moz_annos", annos), ("moz_places_metadata", interactions)],
            wal=True, user_version=87)

    def cookie(cid, host, name, value, created, accessed, expires, secure, httponly, samesite):
        # expiry: ms since 1970 (cookie schema 16+); lastAccessed/creationTime/updateTime: microseconds
        return (cid, "", name, value, host, "/", unix_ms(expires), prtime(accessed), prtime(created),
                secure, httponly, 0, samesite, 2, 0, prtime(created))
    cookies = [
        cookie(1, ".bing.com", "MUID", "1F3C9A0D5E8B6C2147A0E3B9D4C61F58", "2026-09-28 10:08:55.334120",
               "2026-09-28 10:08:55.334120", "2027-11-02 10:08:55.334", 1, 0, 0),
        cookie(2, "mega.nz", "lang", "en", "2026-09-28 10:10:12.802563", "2026-09-28 10:10:41.733902",
               "2027-11-02 10:10:12.802", 1, 0, 1),
    ]
    make_db(os.path.join(prof, "cookies.sqlite"), FF_COOKIES_DDL, [("moz_cookies", cookies)],
            wal=True, user_version=17)

    form = [(1, "email", "drop.box.7731@example.com", 1, prtime("2026-09-28 10:10:41.733902"),
             prtime("2026-09-28 10:10:41.733902"), guid12("form-email"))]
    make_db(os.path.join(prof, "formhistory.sqlite"), FORMHISTORY_DDL, [("moz_formhistory", form)],
            wal=True, user_version=5)

    prefs = "\n".join([
        "// Mozilla User Preferences", "",
        "// DO NOT EDIT THIS FILE.", "",
        'user_pref("browser.startup.homepage_override.mstone", "155.0");',
        'user_pref("places.history.enabled", true);',
        f'user_pref("toolkit.startup.last_success", {unix("2026-09-28 10:08:31")});', ""])
    write(os.path.join(prof, "prefs.js"), prefs.encode())
    write(os.path.join(prof, "times.json"),
          json.dumps({"created": unix_ms(FF_CREATED), "firstUse": None}).encode())
    write(os.path.join(base, "profiles.ini"), (
        "[Install308046B0AF4A39CB]\r\nDefault=Profiles/" + FF_PROFILE + "\r\nLocked=1\r\n\r\n"
        "[Profile0]\r\nName=default-release\r\nIsRelative=1\r\nPath=Profiles/" + FF_PROFILE + "\r\nDefault=1\r\n\r\n"
        "[General]\r\nStartWithLastProfile=1\r\nVersion=2\r\n").encode())
    write(os.path.join(base, "installs.ini"),
          ("[308046B0AF4A39CB]\r\nDefault=Profiles/" + FF_PROFILE + "\r\nLocked=1\r\n").encode())

    for name in ("places.sqlite", "cookies.sqlite", "formhistory.sqlite", "prefs.js"):
        stamp(os.path.join(prof, name), "2026-09-28 10:14:02")
    stamp(os.path.join(prof, "times.json"), FF_CREATED[:19])
    stamp(os.path.join(base, "profiles.ini"), FF_CREATED[:19])
    stamp(os.path.join(base, "installs.ini"), FF_CREATED[:19])


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def stamp(path, when):
    t = calendar.timegm(dt(when).timetuple())
    os.utime(path, (t, t))


def main(outdir):
    edge(outdir)
    firefox(outdir)
    for top, dirs, files in sorted(os.walk(outdir)):
        dirs.sort()
        for f in sorted(files):
            p = os.path.join(top, f)
            print(f"{os.path.getsize(p):>7}  {os.path.relpath(p, outdir)}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
