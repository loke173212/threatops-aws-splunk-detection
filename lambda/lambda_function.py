import json
import urllib3
import os
import base64

http = urllib3.PoolManager()

SPLUNK_HEC_URL = os.environ['SPLUNK_HEC_URL']
SPLUNK_HEC_TOKEN = os.environ['SPLUNK_HEC_TOKEN']

def lambda_handler(event, context):
    for record in event['records']:
        payload = base64.b64decode(record['data'])
        response = http.request(
            'POST',
            f"{SPLUNK_HEC_URL}/services/collector",
            body=json.dumps({
                "event": payload.decode('utf-8')
            }),
            headers={
                'Authorization': f'Splunk {SPLUNK_HEC_TOKEN}',
                'Content-Type': 'application/json'
            }
        )
        print(f"Sent log to Splunk: {response.status}")
    return {'statusCode': 200, 'body': 'Logs forwarded successfully'}
