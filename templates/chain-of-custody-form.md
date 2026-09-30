# Chain of Custody Record

> Copy this file into `Cases/<CASE-ID>/notes/` for every evidence item. Record all times in **UTC**.
> Never delete or overwrite an entry. To correct a mistake, add a new entry that references the one it corrects.

## 1. Case and item

| Field | Value |
|-------|-------|
| Case ID | |
| Evidence item ID | |
| Case name / matter | |
| Legal authority (warrant, consent, engagement letter, policy) | |

## 2. Description of the item

| Field | Value |
|-------|-------|
| Item type (HDD, SSD, USB, phone, laptop, image file, cloud export…) | |
| Make / model | |
| Serial number / IMEI / other unique ID | |
| Capacity | |
| Condition / visible damage | |
| Seal / tamper-evident bag number | |
| Photographs taken (file names) | |

## 3. Seizure / collection

| Field | Value |
|-------|-------|
| Collected by (name, organisation) | |
| Date and time (UTC) | |
| Location (address, room, system name) | |
| Power state when found (on / off / sleep) and actions taken | |
| System clock vs trusted time (clock skew) | |
| Method (seized physically, imaged on site, remote collection, API export) | |
| Witness | |

## 4. Acquisition and integrity

| Field | Value |
|-------|-------|
| Tool and version | |
| Write-blocker used (make / model / software method) | |
| Image file name(s) and format (raw / E01 / AFF4) | |
| Source hash (MD5) | |
| Source hash (SHA-256) | |
| Image verification hash (MD5) | |
| Image verification hash (SHA-256) | |
| Hashes match? (Y/N, and explanation if not, e.g., bad sectors) | |
| Acquisition log file name | |

## 5. Transfer log

Add one row every time the item or an image of it changes hands or location, including moves into and out of storage.

| # | Date/time (UTC) | Released by (name + signature) | Received by (name + signature) | Purpose | From location | To location | Seal intact? | Hash re-verified? |
|--:|-----------------|--------------------------------|--------------------------------|---------|---------------|-------------|:------------:|:-----------------:|
| 1 | | | | | | | | |
| 2 | | | | | | | | |
| 3 | | | | | | | | |

## 6. Final disposition

| Field | Value |
|-------|-------|
| Disposition (returned to owner / destroyed / retained / archived) | |
| Authorised by | |
| Date/time (UTC) | |
| Method (e.g., NIST SP 800-88 purge for media) | |
| Signature | |
