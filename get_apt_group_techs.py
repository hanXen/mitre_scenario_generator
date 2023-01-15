import os.path
import json
import yaml
import requests
from stix2 import Filter
from stix2 import MemoryStore
from stix2.utils import get_type_from_id


G_FILE_PATH = './data/apt_group.json'
G_TECH_FILE_PATH = 'apt_group_techs.json'


def get_data_from_branch(domain, branch="master"):
    """get the ATT&CK STIX data from MITRE/CTI. Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'. Branch should typically be master."""
    stix_json = requests.get(f"https://raw.githubusercontent.com/mitre/cti/{branch}/{domain}/{domain}.json").json()
    return MemoryStore(stix_data=stix_json["objects"])

def get_intrusion_set(thesrc):
    res = {}
    apt_group_list = src.query([Filter('type', '=', 'intrusion-set')])
    for apt_group in apt_group_list:
        res[apt_group.name] = apt_group.id
    print(len(res))
    with open(G_FILE_PATH, "w", encoding='utf-8') as f:
        json.dump(res, f)

def get_techniques_by_group_software(thesrc, group_stix_id):
    # get the malware, tools that the group uses
    group_uses = [
        r for r in thesrc.relationships(group_stix_id, 'uses', source_only=True)
        if get_type_from_id(r.target_ref) in ['malware', 'tool']
    ]

    # get the technique stix ids that the malware, tools use
    software_uses = thesrc.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', 'uses'),
        Filter('source_ref', 'in', [r.source_ref for r in group_uses])
    ])

    #get the techniques themselves
    return thesrc.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('id', 'in', [r.target_ref for r in software_uses])
    ])

src = get_data_from_branch("enterprise-attack")

if not os.path.isfile(G_FILE_PATH):
    get_intrusion_set(src)

APT_GROUP_LIST = json.loads(open("apt_group.json", "r", encoding='utf-8').read())

data = {}
cnt = 0
for name, intrusion_set in APT_GROUP_LIST.items():
    data[name] = {}
    for atk_pattern in get_techniques_by_group_software(src, intrusion_set):
        for tatic in atk_pattern.kill_chain_phases:
            data[name][tatic.phase_name] = {}
            tech_id = atk_pattern.external_references[0].external_id
            description = atk_pattern.description
            data[name][tatic.phase_name][tech_id] = "description"
        cnt += 1
    print(f"[+] processing {name}'s techniques")

print(f"\n[+]Total : {cnt} Techniques.")

with open(G_TECH_FILE_PATH, 'w', encoding='utf-8') as f:
    #json.dump(data, f)
    yaml.dump(data, f)



