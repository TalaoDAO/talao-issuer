import requests
import logging
import json

logging.basicConfig(level=logging.INFO)


def register_tezid(address, id, network,  mode) :
    # check if proof already registered
    url = 'https://tezid.net/api/' + network + '/proofs/' + address
    r = requests.get(url)
    logging.info("check if proof exist : status code = %s", r.status_code)
    if not 199<r.status_code<300 :
        logging.error("API call to TezID rejected %s", r.status_code)
        return False
    if not r.json() :
        return True if register_proof_type(address, id, network, mode) else False
    else :
        proof_registered = False
        for proof in r.json() :
            if proof['id'] == id and proof['verified'] :
                proof_registered = True
                logging.info('Proof already exists on TezID')
                break
    if not proof_registered :
        return True if register_proof_type(address, id, network, mode) else False


def register_proof_type(address, proof_type, network, mode) :
    #[{"id":"test_type","label":"Test_type","meta":{"issuer":"altme"},"verified":true,"register_date":"2022-12-03T11:16:30Z"}]
    url = 'https://tezid.net/api/' + network + '/issuer/altme'
    headers = {
        'Content-Type' : 'application/json',
        'tezid-issuer-key' : mode.tezid_issuer_key     
    }
    data = {
        "address": address,
        "prooftype": proof_type,
        "register": True
    }
    r = requests.post(url, headers=headers, data=json.dumps(data))
    logging.info("Register proof : status code = %s", r.status_code)
    if not 199<r.status_code<300 :
        logging.error("API call to TezID rejected %s", r.status_code)
        return False
    else :
        logging.info('Address has been registered on TezID')
        return True


def issue_sbt(address, metadata, credential_id, mode) :
    metadata_ipfs = add_to_ipfs(metadata, "sbt:" + credential_id , mode)
    if metadata_ipfs :
        metadata_ipfs_url = "ipfs://" + metadata_ipfs
    else :
        return None
    url = 'https://altme-api.dvl.compell.io/mint'
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "transfer_to" : address,
        "ipfs_url" : metadata_ipfs_url
    }
    resp = requests.post(url, data=data, headers=headers)
    if not 199<resp.status_code<300 :
        logging.warning("Get access refused, SBT not sent %s", resp.status_code)
        return None
    return True
 

def add_to_ipfs(data_dict, name, mode) :
    api_key = mode.pinata_api_key
    secret = mode.pinata_secret_api_key
    headers = {
        'Content-Type': 'application/json',
		'pinata_api_key': api_key,
        'pinata_secret_api_key': secret}
    data = {
        'pinataMetadata' : {
            'name' : name
        },
        'pinataContent' : data_dict
    }
    r = requests.post('https://api.pinata.cloud/pinning/pinJSONToIPFS', data=json.dumps(data), headers=headers)
    if not 199<r.status_code<300 :
        logging.warning("POST access to Pinatta refused")
        return None
    else :
	    return r.json()['IpfsHash']


if __name__ == '__main__':
    # ghostnet  KT1K2i7gcbM9YY4ih8urHBDbmYHLUXTWvDYj
    import environment
    myenv='local'
    mode = environment.currentMode(myenv)
    register_tezid("tz1iQNe71wzVCCL5YUSniJekP3qf9cmDosJU", "tezotopia_membershipcard", "ghostnet",  mode)

