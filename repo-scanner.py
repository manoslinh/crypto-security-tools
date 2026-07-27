#!/usr/bin/env python3
"""Batch scanner for secrets across multiple git repos."""

import csv
import io
import json
import os
import re
import shutil
import subprocess
import sys
import argparse
import tempfile
import time
import urllib.request
import urllib.parse
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import NamedTuple


class Finding(NamedTuple):
    repo: str
    file: str
    line: int
    pattern_name: str
    match: str


# ── Pattern definitions ──────────────────────────────────────────────────────

PATTERNS: list[tuple[str, re.Pattern]] = [
    ("API_KEY",           re.compile(r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?", re.I)),
    ("SECRET_KEY",        re.compile(r"(?:secret[_-]?key|client[_-]?secret)\s*[:=]\s*['\"]?[A-Za-z0-9_\-/+=]{16,}['\"]?", re.I)),
    ("PASSWORD",          re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?(?!changeme|xxx|yourpassword|password|test|example|placeholder|dummy)[^\s'\"]{4,}['\"]?", re.I)),
    ("TOKEN",             re.compile(r"(?:token|bearer|auth[_-]?token|access[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{16,}['\"]?", re.I)),
    ("PRIVATE_KEY",       re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("ENCRYPTED_KEY",     re.compile(r"-----BEGIN ENCRYPTED PRIVATE KEY-----")),
    ("AWS_ACCESS_KEY",    re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS_SECRET_KEY",    re.compile(r"(?:aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?", re.I)),
    ("GCP_API_KEY",       re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("AZURE_KEY",         re.compile(r"(?:AccountKey|SharedAccessSignature|DefaultEndpointsProtocol|BlobEndpoint|QueueEndpoint|TableEndpoint)\s*=\s*[A-Za-z0-9/+=]{40,}", re.I)),
    ("BTC_PRIVATE_KEY",   re.compile(r"(?:private[_-]?key|priv[_-]?key|WIF|wif)\s*[:=]\s*['\"]?[0-9a-fA-F]{64}['\"]?", re.I)),
    ("ETH_PRIVATE_KEY",   re.compile(r"(?:private[_-]?key|priv[_-]?key)\s*[:=]\s*['\"]?0x[0-9a-fA-F]{64}['\"]?", re.I)),
    ("MNEMONIC",          re.compile(r"\b([a-z]{3,8})(?:\s+[a-z]{3,8}){11}\b")),
    ("PUBLIC_IP",         re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")),
    ("CONN_STRING",       re.compile(r"(?:mysql|postgres|postgresql|mongodb|redis|amqp|smtp)://[^\s'\"]+", re.I)),
    ("JWT_TOKEN",         re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+")),
]

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", ".nuxt", "vendor", ".terraform",
}

SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot",
    ".pyc", ".pyo", ".so", ".dylib", ".dll",
    ".zip", ".tar", ".gz", ".bz2", ".7z",
    ".lock",
}

MAX_FILE_SIZE = 1_000_000

BIP39_WORDS = frozenset([
    "abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse",
    "access","accident","account","accuse","achieve","acid","acoustic","acquire","across","act",
    "action","actress","actual","adapt","add","addict","address","adjust","admit","adult",
    "advance","advice","aerobic","afford","afraid","again","age","agent","agree","ahead",
    "aim","air","airport","aisle","alarm","album","alcohol","alert","alien","all",
    "alley","allow","almost","alone","alpha","already","also","alter","always","amateur",
    "amazing","among","amount","amused","analyst","anchor","ancient","anger","angle","angry",
    "animal","ankle","announce","annual","another","answer","antenna","antique","anxiety","any",
    "apart","apology","appear","apple","approve","april","arch","arctic","area","arena",
    "argue","arm","armed","armor","army","around","arrange","arrest","arrive","arrow",
    "art","artefact","artist","artwork","ask","aspect","assault","asset","assist","assume",
    "asthma","athlete","atom","attack","attend","attitude","attract","auction","audit","august",
    "aunt","author","auto","autumn","average","avocado","avoid","awake","aware","awesome",
    "awful","awkward","axis","baby","bachelor","bacon","badge","bag","balance","balcony",
    "ball","bamboo","banana","banner","bar","barely","bargain","barrel","base","basic",
    "basket","battle","beach","bean","beauty","because","become","beef","before","begin",
    "behave","behind","believe","below","belt","bench","benefit","best","betray","better",
    "between","beyond","bicycle","bid","bike","bind","biology","bird","birth","bitter",
    "black","blade","blame","blanket","blast","bleak","bless","blind","blood","blossom",
    "blow","blue","blur","blush","board","boat","body","boil","bomb","bone",
    "bonus","book","boost","border","boring","borrow","boss","bottom","bounce","box",
    "boy","bracket","brain","brand","brass","brave","bread","breeze","brick","bridge",
    "brief","bright","bring","brisk","broccoli","broken","bronze","broom","brother","brown",
    "brush","bubble","buddy","budget","buffalo","build","bulb","bulk","bullet","bundle",
    "bunny","burden","burger","burst","bus","business","busy","butter","buyer","buzz",
    "cabbage","cabin","cable","cactus","cage","cake","call","calm","camera","camp",
    "can","canal","cancel","candy","cannon","canoe","canvas","canyon","capable","capital",
    "captain","car","carbon","card","cargo","carpet","carry","cart","case","cash",
    "casino","castle","casual","cat","catalog","catch","category","cattle","caught","cause",
    "caution","cave","ceiling","celery","cement","census","century","cereal","certain","chair",
    "chalk","champion","change","chaos","chapter","charge","chase","cheap","check","cheese",
    "chef","cherry","chest","chicken","chief","child","chimney","choice","choose","chronic",
    "chuckle","chunk","churn","citizen","city","civil","claim","clap","clarify","claw",
    "clay","clean","clerk","clever","cliff","climb","clinic","clip","clock","clog",
    "close","cloth","cloud","clown","club","clump","cluster","clutch","coach","coast",
    "coconut","code","coffee","coil","coin","collect","color","column","combine","come",
    "comfort","comic","common","company","concert","conduct","confirm","congress","connect","consider",
    "control","convince","cook","cool","copper","copy","coral","core","corn","correct",
    "cost","cotton","couch","country","couple","course","cousin","cover","coyote","crack",
    "cradle","craft","cram","crane","crash","crater","crawl","crazy","cream","credit",
    "creek","crew","cricket","crime","crisp","critic","crop","cross","crouch","crowd",
    "crucial","cruel","cruise","crumble","crush","cry","crystal","cube","culture","cup",
    "cupboard","curious","current","curtain","curve","cushion","custom","cute","cycle","dad",
    "damage","damp","dance","danger","daring","dash","daughter","dawn","day","deal",
    "debate","debris","decade","december","decide","decline","decorate","decrease","deer","defense",
    "define","defy","degree","delay","deliver","demand","demise","denial","dentist","deny",
    "depart","depend","deposit","depth","deputy","derive","describe","desert","design","desk",
    "despair","destroy","detail","detect","develop","device","devote","diagram","dial","diamond",
    "diary","dice","diesel","diet","differ","digital","dignity","dilemma","dinner","dinosaur",
    "direct","dirt","disagree","discover","disease","dish","dismiss","disorder","display","distance",
    "divert","divide","divorce","dizzy","doctor","document","dog","doll","dolphin","domain",
    "donate","donkey","donor","door","dose","double","dove","draft","dragon","drama",
    "drastic","draw","dream","dress","drift","drill","drink","drip","drive","drop",
    "drum","dry","duck","dumb","dune","during","dust","dutch","duty","dwarf",
    "dynamic","dying","eager","eagle","early","earn","earth","easily","east","easy",
    "echo","ecology","edge","edit","educate","effort","egg","eight","either","elbow",
    "elder","electric","elegant","element","elephant","elevator","elite","else","embark","embody",
    "embrace","emerge","emotion","employ","empower","empty","enable","encourage","end","endless",
    "endorse","enemy","energy","enforce","engage","engine","enhance","enjoy","enlist","enough",
    "enrich","enroll","ensure","enter","entire","entry","envelope","episode","equal","equip",
    "era","erase","erode","erosion","error","erupt","escape","essay","essence","estate",
    "eternal","ethics","evidence","evil","evoke","evolve","exact","example","excess","exchange",
    "excite","exclude","excuse","execute","exercise","exhaust","exhibit","exile","exist","exit",
    "exotic","expand","expect","expire","explain","expose","express","extend","extra","eye",
    "eyebrow","fabric","face","faculty","fade","faint","faith","fall","false","fame",
    "family","famous","fan","fancy","fantasy","farm","fashion","fat","fatal","father",
    "fatigue","fault","favorite","feature","february","federal","fee","feed","feel","female",
    "fence","festival","fetch","fever","few","fiber","fiction","field","figure","file",
    "film","filter","final","find","fine","finger","finish","fire","firm","fiscal",
    "fish","fit","fitness","fix","flag","flame","flash","flat","flavor","flee",
    "flight","flip","float","flock","floor","flower","fluid","flush","fly","foam",
    "focus","fog","foil","fold","follow","food","foot","force","forest","forget",
    "fork","fortune","forum","forward","fossil","foster","found","fox","fragile","frame",
    "frequent","fresh","friend","fringe","frog","front","frost","frown","frozen","fruit",
    "fuel","fun","funny","furnace","fury","future","gadget","gain","galaxy","gallery",
    "game","gap","garage","garbage","garden","garlic","garment","gas","gasp","gate",
    "gather","gauge","gaze","general","genius","genre","gentle","genuine","gesture","ghost",
    "giant","gift","giggle","ginger","giraffe","girl","give","glad","glance","glare",
    "glass","glide","glimpse","globe","gloom","glory","glove","glow","glue","goat",
    "goddess","gold","good","goose","gorilla","gospel","gossip","govern","gown","grab",
    "grace","grain","grant","grape","grass","gravity","great","green","grid","grief",
    "grit","grocery","group","grow","grunt","guard","guess","guide","guilt","guitar",
    "gun","gym","habit","hair","half","hammer","hamster","hand","happy","harbor",
    "hard","harsh","harvest","hat","have","hawk","hazard","head","health","heart",
    "heavy","hedgehog","height","hello","helmet","help","hen","hero","hip","hire",
    "history","hobby","hockey","hold","hole","holiday","hollow","home","honey","hood",
    "hope","horn","horror","horse","hospital","host","hotel","hour","hover","hub",
    "huge","human","humble","humor","hundred","hungry","hunt","hurdle","hurry","hurt",
    "husband","hybrid","ice","icon","idea","identify","idle","ignore","ill","illegal",
    "illness","image","imitate","immense","immune","impact","impose","improve","impulse","inch",
    "include","income","increase","index","indicate","indoor","industry","infant","inflict","inform",
    "initial","inject","inmate","inner","innocent","input","inquiry","insane","insect","inside",
    "inspire","install","intact","interest","into","invest","invite","involve","iron","island",
    "isolate","issue","item","ivory","jacket","jaguar","jar","jazz","jealous","jeans",
    "jelly","jewel","job","join","joke","journey","joy","judge","juice","jump",
    "jungle","junior","junk","just","kangaroo","keen","keep","ketchup","key","kick",
    "kid","kidney","kind","kingdom","kiss","kit","kitchen","kite","kitten","kiwi",
    "knee","knife","knock","know","lab","label","labor","ladder","lady","lake",
    "lamp","language","laptop","large","later","latin","laugh","laundry","lava","law",
    "lawn","lawsuit","layer","lazy","leader","leaf","learn","leave","lecture","left",
    "leg","legal","legend","leisure","lemon","lend","length","lens","leopard","lesson",
    "letter","level","liberty","library","license","life","lift","light","like","limb",
    "limit","link","lion","liquid","list","little","live","lizard","load","loan",
    "lobster","local","lock","logic","lonely","long","loop","lottery","loud","lounge",
    "love","loyal","lucky","luggage","lumber","lunar","lunch","luxury","lyrics","machine",
    "mad","magic","magnet","maid","mail","major","make","mammal","man","manage",
    "mandate","mango","mansion","manual","map","marble","march","margin","marine","market",
    "marriage","mask","mass","master","match","material","math","matrix","matter","maximum",
    "maze","meadow","mean","measure","meat","mechanic","medal","media","melody","melt",
    "member","memory","mention","menu","mercy","merge","merit","mess","message","metal",
    "method","middle","milk","million","mimic","mind","minimum","minor","minute","miracle",
    "mirror","misery","miss","mistake","mix","mixed","mixture","mobile","model","modify",
    "mom","moment","monitor","monkey","monster","month","moon","moral","more","morning",
    "mosquito","mother","motion","motor","mountain","mouse","move","movie","much","muffin",
    "mule","multiply","muscle","museum","mushroom","music","must","mutual","myself","mystery",
    "myth","naive","name","napkin","narrow","nasty","nation","nature","near","neck",
    "need","negative","neglect","neither","nephew","nerve","nest","net","network","neutral",
    "never","news","next","nice","night","noble","noise","nominee","noodle","normal",
    "north","nose","notable","nothing","notice","novel","now","nuclear","number","nurse",
    "nut","oak","obey","object","oblige","obscure","observe","obtain","obvious","occur",
    "ocean","october","odor","off","offer","office","often","oil","okay","old",
    "olive","olympic","omit","once","one","onion","online","only","open","opera",
    "opinion","oppose","option","orange","orbit","orchard","order","ordinary","organ","orient",
    "original","orphan","ostrich","other","outdoor","outer","output","outside","oval","oven",
    "over","owner","oxygen","oyster","ozone","pact","paddle","page","pair","palace",
    "palm","panda","panel","panic","panther","paper","parade","parent","park","parrot",
    "party","pass","patch","path","patient","patrol","pattern","pause","pave","payment",
    "peace","peanut","pear","peasant","pen","penalty","pencil","people","pepper","perfect",
    "permit","person","pet","phone","photo","phrase","physical","piano","picnic","picture",
    "piece","pig","pigeon","pill","pilot","pink","pioneer","pipe","pistol","pitch",
    "pizza","place","planet","plastic","plate","play","please","pledge","pluck","plug",
    "plunge","poem","poet","point","polar","pole","police","pond","pony","pool",
    "popular","portion","position","possible","post","potato","pottery","poverty","powder","power",
    "practice","praise","predict","prefer","prepare","present","pretty","prevent","price","pride",
    "primary","print","priority","prison","private","prize","problem","process","produce","profit",
    "program","project","promote","proof","property","prosper","protect","proud","provide","public",
    "pudding","pull","pulp","pulse","pumpkin","punch","pupil","puppy","purchase","pursuit",
    "put","puzzle","pyramid","quality","quantum","quarter","queen","query","quest","queue",
    "quick","quit","quiz","quote","rabbit","raccoon","race","rack","radar","radio",
    "rage","rail","rain","raise","rally","ramp","ranch","random","range","rapid",
    "rare","rate","rather","raven","raw","razor","ready","reason","rebel","rebuild",
    "recall","receive","recipe","record","recycle","reduce","reflect","reform","region","regret",
    "regular","reject","relax","release","relief","rely","remain","remember","remind","remove",
    "render","renew","rent","reopen","repair","repeat","replace","report","require","rescue",
    "resemble","resist","resource","response","result","retire","retreat","return","reunion","reveal",
    "review","reward","rhythm","rice","rich","ride","ridge","rifle","right","rigid",
    "ring","riot","ripple","risk","ritual","rival","river","road","roast","robot",
    "robust","rocket","romance","roof","rookie","room","rose","rotate","rough","round",
    "route","royal","rubber","rude","rug","rule","run","runway","rural","sad",
    "saddle","sadness","safe","sail","salad","salmon","salon","salt","salute","same",
    "sample","sand","satisfy","satoshi","sauce","sausage","save","say","scale","scan",
    "scare","scatter","scene","scheme","school","science","scissors","scorpion","scout","scrap",
    "screen","script","scrub","sea","search","season","seat","second","secret","section",
    "security","seed","seek","segment","select","sell","seminar","senior","sense","sentence",
    "series","service","session","settle","setup","seven","shadow","shaft","shallow","share",
    "shed","shell","sheriff","shield","shift","shine","ship","shiver","shock","shoe",
    "shoot","shop","short","shoulder","shove","shrimp","shrug","shuffle","shy","sibling",
    "sick","side","siege","sight","sign","silent","silk","silly","silver","similar",
    "simple","since","sing","siren","sister","situate","six","size","skate","sketch",
    "ski","skill","skin","skirt","skull","slab","slam","sleep","slender","slice",
    "slide","slight","slim","slogan","slot","slow","slush","small","smart","smile",
    "smoke","smooth","snack","snake","snap","sniff","snow","soap","soccer","social",
    "sock","soda","soft","solar","soldier","solid","solution","solve","someone","song",
    "soon","sorry","sort","soul","sound","soup","source","south","space","spare",
    "spatial","spawn","speak","special","speed","spell","spend","sphere","spice","spider",
    "spike","spin","spirit","split","sponsor","spoon","sport","spot","spray","spread",
    "spring","spy","square","squeeze","squirrel","stable","stadium","staff","stage","stairs",
    "stamp","stand","start","state","stay","steak","steel","stem","step","stereo",
    "stick","still","sting","stock","stomach","stone","stool","story","stove","strategy",
    "street","strike","strong","struggle","student","stuff","stumble","style","subject","submit",
    "subway","success","such","sudden","suffer","sugar","suggest","suit","summer","sun",
    "sunny","sunset","super","supply","supreme","sure","surface","surge","surprise","surround",
    "survey","suspect","sustain","swallow","swamp","swap","swarm","swear","sweet","swim",
    "swing","switch","sword","symbol","symptom","syrup","system","table","tackle","tag",
    "tail","talent","talk","tank","tape","target","task","taste","tattoo","taxi",
    "teach","team","tell","ten","tenant","tennis","tent","term","test","text",
    "thank","that","theme","then","theory","there","they","thing","this","thought",
    "three","thrive","throw","thumb","thunder","ticket","tide","tiger","tilt","timber",
    "time","tiny","tip","tired","tissue","title","toast","tobacco","today","toddler",
    "toe","together","toilet","token","tomato","tomorrow","tone","tongue","tonight","tool",
    "tooth","top","topic","topple","torch","tornado","tortoise","toss","total","tourist",
    "toward","tower","town","toy","track","trade","traffic","tragic","train","transfer",
    "trap","trash","travel","tray","treat","tree","trend","trial","tribe","trick",
    "trigger","trim","trip","trophy","trouble","truck","true","truly","trumpet","trust",
    "truth","try","tube","tuna","tunnel","turkey","turn","turtle","twelve","twenty",
    "twice","twin","twist","two","type","typical","ugly","umbrella","unable","unaware",
    "uncle","uncover","under","undo","unfair","unfold","unhappy","uniform","union","unique",
    "unit","universe","unknown","unlock","until","unusual","unveil","update","upgrade","uphold",
    "upon","upper","upset","urban","usage","use","used","useful","useless","usual",
    "utility","vacant","vacuum","vague","valid","valley","valve","van","vanish","vapor",
    "various","vast","vault","vehicle","velvet","vendor","venture","venue","verb","version",
    "very","vessel","veteran","viable","vibrant","vicious","victory","video","view","village",
    "vintage","violin","virtual","virus","visa","visit","visual","vital","vivid","vocal",
    "voice","void","volcano","volume","vote","voyage","wage","wagon","wait","walk",
    "wall","walnut","want","warfare","warm","warrior","wash","wasp","waste","water",
    "wave","way","wealth","weapon","weave","weed","week","weight","weird","welcome",
    "well","west","wet","whale","what","wheat","wheel","when","where","whip",
    "whisper","wide","width","wife","wild","will","win","window","wine","wing",
    "wink","winner","winter","wire","wisdom","wise","wish","witness","wolf","woman",
    "wonder","wood","wool","word","work","world","worry","worth","wrap","wreck",
    "wrist","write","wrong","yard","year","yellow","you","young","youth","zebra",
    "zero","zone","zoo",
])


def is_rfc1918(ip: str) -> bool:
    """Check if IP is in RFC1918 private range, loopback, or link-local."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        first, second = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    if first == 0:
        return True  # 0.0.0.0
    if first == 10:
        return True
    if first == 127:
        return True  # loopback
    if first == 169 and second == 254:
        return True  # link-local
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    return False


def is_valid_mnemonic(text: str) -> bool:
    words = text.lower().split()
    return len(words) in (12, 24) and all(w in BIP39_WORDS for w in words)


# ── GitHub API helpers ───────────────────────────────────────────────────────

def github_api(endpoint: str, token: str | None = None) -> dict | list:
    """Call GitHub API. Returns parsed JSON. Handles errors and rate limiting."""
    url = f"https://api.github.com{endpoint}"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "repo-scanner"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            remaining = resp.headers.get("X-RateLimit-Remaining")
            if remaining and int(remaining) < 5:
                reset = int(resp.headers.get("X-RateLimit-Reset", 0))
                wait = max(reset - int(time.time()), 1)
                print(f"  Rate limit low ({remaining} left). Waiting {wait}s...", file=sys.stderr)
                time.sleep(wait)
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"  GitHub API rate limit hit or forbidden. Use --token for higher limits.", file=sys.stderr)
        elif e.code == 404:
            print(f"  Not found: {endpoint}", file=sys.stderr)
        else:
            print(f"  GitHub API error {e.code}: {e.reason}", file=sys.stderr)
        return [] if "items" in endpoint or "repos" in endpoint else {}
    except urllib.error.URLError as e:
        print(f"  GitHub API connection error: {e.reason}", file=sys.stderr)
        return []
    except json.JSONDecodeError:
        print(f"  GitHub API returned non-JSON response for {endpoint}", file=sys.stderr)
        return []


def github_api_paginated(endpoint: str, token: str | None = None, per_page: int = 100) -> list:
    """Paginate through a GitHub API list endpoint."""
    results = []
    page = 1
    while True:
        sep = "&" if "?" in endpoint else "?"
        data = github_api(f"{endpoint}{sep}per_page={per_page}&page={page}", token)
        if not data:
            break
        results.extend(data)
        if len(data) < per_page:
            break
        page += 1
    return results


def get_org_repos(org: str, token: str | None = None) -> list[str]:
    """Get all repos for a GitHub org. Returns list of owner/repo strings."""
    repos = github_api_paginated(f"/orgs/{org}/repos", token)
    return [r["full_name"] for r in repos]


def get_user_repos(user: str, token: str | None = None) -> list[str]:
    """Get all repos for a GitHub user. Returns list of owner/repo strings."""
    repos = github_api_paginated(f"/users/{user}/repos", token)
    return [r["full_name"] for r in repos]


def search_repos(query: str, token: str | None = None) -> list[str]:
    """Search GitHub for repos matching a query. Returns list of owner/repo strings.
    GitHub search API caps at 1000 results total."""
    encoded = urllib.parse.quote(query)
    results = []
    page = 1
    while len(results) < 1000:
        data = github_api(f"/search/repositories?q={encoded}&per_page=100&page={page}", token)
        items = data.get("items", [])
        if not items:
            break
        results.extend([r["full_name"] for r in items])
        if len(items) < 100:
            break
        page += 1
    if len(results) >= 1000:
        print(f"  Note: GitHub search API caps at 1000 results. Refine query for more.", file=sys.stderr)
    return results


# ── Repo list loaders ────────────────────────────────────────────────────────

def load_repos_from_csv(path: str) -> list[str]:
    """Load repos from CSV. Expects column 'repo' or first column as owner/repo."""
    repos = []
    with open(path, newline="") as f:
        content = f.read()
    # Handle CSV with no header row (all values in first column)
    lines = content.strip().splitlines()
    if not lines:
        return repos
    first_line = lines[0]
    # If first line contains a comma and looks like a header, use DictReader
    if "," in first_line and not re.match(r"^[^,]+/[^,]+$", first_line):
        reader = csv.DictReader(io.StringIO(content))
        fieldnames = reader.fieldnames or []
        if not fieldnames:
            return repos
        repo_col = "repo" if "repo" in fieldnames else fieldnames[0]
        for row in reader:
            val = row.get(repo_col, "").strip()
            if val and "/" in val:
                repos.append(val)
    else:
        # No header, treat first column as owner/repo
        for line in lines:
            parts = line.split(",")
            val = parts[0].strip().strip('"').strip("'")
            if val and "/" in val:
                repos.append(val)
    return repos


def load_repos_from_json(path: str) -> list[str]:
    """Load repos from JSON. Accepts list of strings, list of objects, or nested structures."""
    with open(path) as f:
        data = json.load(f)
    # Handle flat list of strings
    if isinstance(data, list):
        if data and isinstance(data[0], str):
            return [r for r in data if "/" in r]
        if data and isinstance(data[0], dict):
            return [r["repo"] for r in data if "repo" in r]
        return []
    # Handle nested structures like {"repos": [...]} or {"items": [...]}
    if isinstance(data, dict):
        for key in ("repos", "items", "repositories", "data"):
            if key in data and isinstance(data[key], list):
                items = data[key]
                if items and isinstance(items[0], str):
                    return [r for r in items if "/" in r]
                if items and isinstance(items[0], dict):
                    return [r.get("repo", r.get("full_name", "")) for r in items if r.get("repo") or r.get("full_name")]
        return []
    return []


# ── Clone + scan logic ───────────────────────────────────────────────────────

def should_skip(path: str, exclude_patterns: list[str] | None = None) -> bool:
    p = Path(path)
    if any(part in SKIP_DIRS for part in p.parts):
        return True
    suffix = p.suffix.lower()
    name = p.name.lower()
    if suffix in SKIP_EXTS:
        return True
    if name.endswith(".min.js") or name.endswith(".min.css"):
        return True
    if exclude_patterns:
        for pattern in exclude_patterns:
            if re.search(pattern, path):
                return True
    return False


def is_binary(filepath: Path) -> bool:
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(8192)
        return b"\x00" in chunk
    except (OSError, PermissionError):
        return True


def get_tracked_files(repo: Path) -> list[str]:
    try:
        result = subprocess.run(
            ["git", "ls-files"],
            cwd=repo,
            capture_output=True,
            text=True,
            check=True,
        )
        return [f.strip() for f in result.stdout.splitlines() if f.strip()]
    except subprocess.CalledProcessError:
        return []


def scan_file(filepath: Path) -> list[tuple[str, int, str]]:
    """Scan file, return list of (pattern_name, line_num, matched_text)."""
    findings = []
    if filepath.stat().st_size > MAX_FILE_SIZE:
        return findings
    if is_binary(filepath):
        return findings
    try:
        content = filepath.read_text(errors="ignore")
    except (OSError, PermissionError):
        return findings
    for line_num, line in enumerate(content.splitlines(), start=1):
        for name, pattern in PATTERNS:
            match = pattern.search(line)
            if match:
                matched_text = match.group()
                if name == "PUBLIC_IP" and is_rfc1918(matched_text):
                    continue
                if name == "MNEMONIC" and not is_valid_mnemonic(matched_text):
                    continue
                findings.append((name, line_num, matched_text[:100]))
    return findings


def clone_repo(repo: str, dest: Path, token: str | None = None) -> Path | None:
    """Clone a repo. Returns path or None on failure. Token passed via http.extraHeader to avoid leaking in URL."""
    url = f"https://github.com/{repo}.git"
    repo_dir = dest / repo.replace("/", "_")
    cmd = ["git", "clone", "--depth", "1"]
    if token:
        cmd.extend(["-c", f"http.extraHeader=Authorization: Bearer {token}"])
    cmd.extend([url, str(repo_dir)])
    try:
        subprocess.run(
            cmd,
            capture_output=True,
            check=True,
            timeout=120,
        )
        return repo_dir
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None


def scan_repo(repo: str, repo_dir: Path, exclude_patterns: list[str], jobs: int) -> list[Finding]:
    """Scan a cloned repo and return findings."""
    findings = []
    files = get_tracked_files(repo_dir)

    def process_file(f: str) -> list[Finding]:
        if should_skip(f, exclude_patterns):
            return []
        filepath = repo_dir / f
        if not filepath.is_file():
            return []
        try:
            local_findings = scan_file(filepath)
            return [Finding(repo=repo, file=f, line=line, pattern_name=name, match=match) for name, line, match in local_findings]
        except (OSError, PermissionError):
            return []

    with ThreadPoolExecutor(max_workers=jobs) as executor:
        futures = {executor.submit(process_file, f): f for f in files}
        for future in as_completed(futures):
            try:
                findings.extend(future.result())
            except Exception:
                pass

    return findings


def delete_repo(repo_dir: Path):
    """Remove cloned repo directory."""
    shutil.rmtree(repo_dir, ignore_errors=True)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Batch scanner for secrets across multiple git repos",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Scan a local repo:
    %(prog)s /path/to/repo

  Scan repos from CSV file:
    %(prog)s --csv repos.csv

  Scan repos from JSON file:
    %(prog)s --json-file repos.json

  Scan all repos from a GitHub org:
    %(prog)s --org my-company

  Scan all repos from a GitHub user:
    %(prog)s --user octocat

  Search GitHub for repos:
    %(prog)s --search "filename:.env"

  Search with multiple keywords (combined with AND):
    %(prog)s --search ".env" --search "bitcoin"

  Search repos created in 2024:
    %(prog)s --search ".env" --search "bitcoin" --created-after 2024-01-01

  Combine sources:
    %(prog)s --org my-company --csv extra-repos.csv
""",
    )

    # Input sources (mutually exclusive-ish, can combine)
    input_group = parser.add_argument_group("input sources")
    input_group.add_argument("repo", nargs="?", help="Local repo path (scan without cloning)")
    input_group.add_argument("--csv", dest="csv_file", help="CSV file with repos (column 'repo' or first column)")
    input_group.add_argument("--json-file", dest="json_file", help="JSON file with repos")
    input_group.add_argument("--org", help="GitHub org (scan all repos)")
    input_group.add_argument("--user", help="GitHub user (scan all repos)")
    input_group.add_argument("--search", action="append", help="GitHub search keywords (repeatable, combined with AND)")
    input_group.add_argument("--created-after", help="Only repos created after date (YYYY-MM-DD)")
    input_group.add_argument("--created-before", help="Only repos created before date (YYYY-MM-DD)")

    # Options
    parser.add_argument("-v", "--verbose", action="store_true", help="Show matched content")
    parser.add_argument("--json-output", action="store_true", help="Output as JSON")
    parser.add_argument("--exclude", action="append", default=[], help="Regex pattern to exclude files (repeatable)")
    parser.add_argument("-j", "--jobs", type=int, default=4, help="Parallel workers (default: 4)")
    parser.add_argument("--token", help="GitHub token (or set GITHUB_TOKEN env var)")
    parser.add_argument("--keep", action="store_true", help="Don't delete cloned repos after scanning")
    parser.add_argument("--limit", type=int, default=0, help="Max repos to scan (0 = no limit)")

    args = parser.parse_args()

    token = args.token or os.environ.get("GITHUB_TOKEN")

    # Collect all repos to scan
    repos_to_scan: list[str] = []

    if args.repo:
        repos_to_scan.append(("local", args.repo))

    if args.csv_file:
        for repo in load_repos_from_csv(args.csv_file):
            repos_to_scan.append(("clone", repo))

    if args.json_file:
        for repo in load_repos_from_json(args.json_file):
            repos_to_scan.append(("clone", repo))

    if args.org:
        print(f"Fetching repos from org: {args.org}", file=sys.stderr)
        for repo in get_org_repos(args.org, token):
            repos_to_scan.append(("clone", repo))

    if args.user:
        print(f"Fetching repos from user: {args.user}", file=sys.stderr)
        for repo in get_user_repos(args.user, token):
            repos_to_scan.append(("clone", repo))

    if args.search:
        query = " ".join(args.search)
        if args.created_after:
            query += f" created:>={args.created_after}"
        if args.created_before:
            query += f" created:<={args.created_before}"
        print(f"Searching GitHub: {query}", file=sys.stderr)
        for repo in search_repos(query, token):
            repos_to_scan.append(("clone", repo))

    if not repos_to_scan:
        parser.print_help()
        sys.exit(1)

    if args.limit > 0:
        repos_to_scan = repos_to_scan[:args.limit]
        print(f"Limiting to {args.limit} repos", file=sys.stderr)

    # Scan
    all_findings: list[Finding] = []
    scanned_count = 0
    failed_count = 0

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        for mode, repo in repos_to_scan:
            if mode == "local":
                repo_path = Path(repo).resolve()
                if not (repo_path / ".git").is_dir():
                    print(f"  [SKIP] {repo} is not a git repo", file=sys.stderr)
                    failed_count += 1
                    continue
                print(f"  [SCAN] {repo}", file=sys.stderr)
                findings = scan_repo(repo, repo_path, args.exclude, args.jobs)
                all_findings.extend(findings)
                scanned_count += 1
            else:
                print(f"  [CLONE] {repo}", file=sys.stderr)
                repo_dir = clone_repo(repo, tmp, token)
                if not repo_dir:
                    print(f"  [FAIL] {repo}", file=sys.stderr)
                    failed_count += 1
                    continue
                findings = scan_repo(repo, repo_dir, args.exclude, args.jobs)
                all_findings.extend(findings)
                scanned_count += 1
                if not args.keep:
                    delete_repo(repo_dir)

    # Output
    if args.json_output:
        print(json.dumps([f._asdict() for f in all_findings], indent=2))
    else:
        print(f"\nScanned {scanned_count} repos ({failed_count} failed). Found {len(all_findings)} issues.\n", file=sys.stderr)
        if all_findings:
            for f in all_findings:
                line = f"  [{f.pattern_name}] {f.repo}/{f.file}:{f.line}"
                print(line)
                if args.verbose:
                    print(f"    -> {f.match[:120]}")
            print()


if __name__ == "__main__":
    main()
