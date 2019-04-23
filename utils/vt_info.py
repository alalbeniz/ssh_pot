import argparse
import requests
import hashlib
import paramiko
import os
import sys
import time
import json

from ddbb.connections import Sample

APP_DIR = os.path.dirname(os.path.realpath(__file__))
paramiko.util.log_to_file(os.path.join(APP_DIR, "../log/server.log"))
logger = paramiko.util.get_logger('paramiko')

MD5SUM  = 'md5sum'
SHA1    = 'sha1sum'
SHA256  = 'sha256sum'
methods = (MD5SUM, SHA1, SHA256)

def hashing(filename, method=SHA1):
    """
    Method for hashing the files intended for the report.
    It can be done in:
        'md5sum'
        'sha1sum'
        'sha256sum'
    """
    if method == MD5SUM:
        hash_file = hashlib.md5()
    elif method == SHA256:
        hash_file = hashlib.sha256()
    else:
        hash_file = hashlib.sha1()

    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_file.update(chunk)
    return hash_file.hexdigest()


class VirusTotal(object):
    def __init__(self):
        self.apikey = ""
        self.URL_BASE = "https://www.virustotal.com/vtapi/v2/"
        self.HTTP_OK = 200
        self.HTTP_NO_CONTENT = 204

        # whether the API_KEY is a public API. limited to 4 per min if so.
        self.is_public_api = True
        # whether a retrieval request is sent recently
        self.PUBLIC_API_LICENSE_WARNING = False
        # if needed (public API), sleep this amount of time between requests
        self.PUBLIC_API_SLEEP_TIME = 60


    def retrieve_files_reports(self, filename):
        """
        Retrieve file report
        @param filename: file data
        """

        res = self.retrieve_report(hashing(filename, SHA256))

        if res.status_code == self.HTTP_OK:
            resmap = json.loads(res.text)
            #if not self.is_verboselog:
#                self.logger.info("retrieve report: %s, HTTP: %d, response_code: %d, scan_date: %s, positives/total: %d/%d",
#                        os.path.basename(filename), res.status_code, resmap["response_code"], resmap["scan_date"], resmap["positives"], resmap["total"])
#            else:
#                self.logger.info("retrieve report: %s, HTTP: %d, content: %s", os.path.basename(filename), res.status_code, res.text)
            return resmap
        elif res.status_code == self.HTTP_NO_CONTENT:
            logger.warning("Free license finished, time to sleep")
            time.sleep(self.PUBLIC_API_SLEEP_TIME)
        else:
            logger.warning("retrieve report: %s, HTTP: %d", os.path.basename(filename), res.status_code)



    def retrieve_from_checksum(self, checksum):
        """
        Retrieve file report from checksum
        @param checksum: file checksum, better use sha256sum
        """
        res = self.retrieve_report(checksum)
        if res.status_code == self.HTTP_OK:
            logger.info('Retrieving [{}] file info'.format(checksum))
            resmap = json.loads(res.text)
            return resmap
#            if not self.is_verboselog:
#                self.logger.info("retrieve report: %s, HTTP: %d, response_code: %d, scan_date: %s, positives/total: %d/%d",
#                        checksum, res.status_code, resmap["response_code"], resmap["scan_date"], resmap["positives"], resmap["total"])
#            else:
#                self.logger.info("retrieve report: %s, HTTP: %d, content: %s", os.path.basename(filename), res.status_code, res.text)

        elif res.status_code == self.HTTP_NO_CONTENT:
            logger.warning("Free license finished, time to sleep")
            time.sleep(self.PUBLIC_API_SLEEP_TIME)
            if not self.PUBLIC_API_LICENSE_WARNING:
                self.PUBLIC_API_LICENSE_WARNING = True
                self.retrieve_from_checksum(checksum)
            else:
                self.PUBLIC_API_LICENSE_WARNING = False
                return None
        else:
            logger.warning("Could not retrieve report: %s, HTTP: %d", checksum, res.status_code)


    def retrieve_report(self, checksum):
        """
        Retrieve file's report from checksum
        4 retrieval per min if only public API used
        @param checksum: file checksum, better use sha256sum
        """
#        if self.has_sent_retrieve_req and self.is_public_api:
#            time.sleep(self.PUBLIC_API_SLEEP_TIME)

        url = self.URL_BASE + "file/report"
        params = {"apikey": self.apikey, "resource": checksum}
        res = requests.post(url, data=params)
        self.has_sent_retrieve_req = True
        return res


    def extract_info(self, data, sample):
        try:
            sample.sha1sum     = data['sha1']
            sample.md5sum      = data['md5']
            sample.positives   = data['positives']
            sample.total       = data['total']
            sample.scan_result = data['response_code']
            
            sample.vt_link     = data['permalink']
            
            results = []
            for scan in data['scans'].values():
                if scan['detected'] == True:
                    results.append(scan['result'])
            
            sample.raw_result  = data
            sample.save()

        except:
            logger.exception('Error extracting sample info')


def get_samples_info(vt, samples):
    logger.info('{} samples to search'.format(len(samples)))
    for sample in samples:
        sample_path = APP_DIR + '/../samples/' + sample.name
        sample_hash = hashing(sample_path, SHA256)

        try:
            sample.sha256sum = sample_hash
            sample.save()
        except:
            logger.exception('Error saving sample {} - {} hash info'.format(sample.id, sample.name))

        vt_response = vt.retrieve_from_checksum(sample_hash)

        if vt_response['response_code'] == 1:
            vt.extract_info(vt_response, sample)



if __name__ == "__main__":
    vt = VirusTotal()
    try:
        with open(APP_DIR + '/.vt') as keyfile:
            vt.apikey = keyfile.read().strip()
    except Exception as e:
        logger.error('Error loading virustotal api key')
        sys.exit(1)

    parser = argparse.ArgumentParser(description='Virustotal Samples Scan')
    parser.add_argument("-n", "--new", help="scan unscanned files", action="store_true")
    parser.add_argument("-u", "--unknown", help="scan files without information", action="store_true")
    args = parser.parse_args()


    if args.new:
        samples = Sample.select().where(Sample.scan_result == None)
        if samples:
            get_samples_info(vt, samples)
        else:
            logger.info('No samples to search')


    if args.unknown:
        samples = Sample.select().where(Sample.scan_result == 0)
        if samples:
            get_samples_info(vt, samples)
        else:
            logger.info('No samples to search')


#    logger.info('{} samples to search'.format(len(samples)))
#    for sample in samples:
#        sample_path = APP_DIR + '/../samples/' + sample.name
#        sample_hash = hashing(sample_path, SHA256)
#
#        try:
#            sample.sha256sum = sample_hash
#            sample.save()
#        except:
#            logger.exception('Error saving sample {} - {} hash info'.format(sample.id, sample.name))
#
#        vt_response = vt.retrieve_from_checksum(sample_hash)
#
#        if vt_response['response_code'] = 1:
#            vt.extract_info(vt_response, sample)


#    if args.unknown:
#        samples = Sample.select().where(Sample.scan_result == 0)
#        for sample in samples:
#            sample_path = APP_DIR + '/../samples/'  + sample.name
#            if sample.sha256sum:
#                sample_hash = sample.sha256sum
#            else:
#                sample_hash = hashing(sample_path, SHA256)
#                try:
#                    sample.sha256sum = sample_hash
#                    sample.save()
#                except:
#                    logger.exception('Error saving sample {} - {} hash info'.format(sample.id, sample.name))
#
#            vt_response = vt.retrieve_files_reports(sample_path)
#
#            if vt_response['response_code'] = 1:
#                vt.extract_info(vt_response, sample)

