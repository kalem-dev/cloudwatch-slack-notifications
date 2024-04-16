import urllib3
import json
import os

# Needed to decrypt KMS key
import boto3
from base64 import b64decode

# Original code from here:
# https://antonputra.com/amazon/send-aws-cloudwatch-alarms-to-slack/

# How to subscribe this Lambda function to SNS topics from other accounts: 
# https://repost.aws/knowledge-center/sns-with-crossaccount-lambda-subscription

# Decrypts Slack webhook URL which is an encrypted environment variable
# Decrypt code should run once and variables stored outside ofthe function
# handler so that these are decrypted once per container
slack_url = boto3.client('kms').decrypt(
    CiphertextBlob=b64decode(os.environ['SLACK_WEBHOOK_URL']),
    EncryptionContext={'LambdaFunctionName': os.environ['AWS_LAMBDA_FUNCTION_NAME']}
)['Plaintext'].decode('utf-8')

# Needed to send POST requests to Slack
http = urllib3.PoolManager()
    
def get_alarm_attributes(sns_message_str):
    sns_message = json.loads(sns_message_str)
    alarm = dict()
    
    alarm['name'] = sns_message['AlarmName']
    alarm['reason'] = sns_message['NewStateReason']
    alarm['state'] = sns_message['NewStateValue']
    alarm['region'] = sns_message['AlarmArn'].split(':')[3] # Extracts region from AlarmArn for URL
    alarm['accountid'] = sns_message['AWSAccountId']
    
    # Not using these currently:
    # alarm['description'] = sns_message['AlarmDescription']
    # alarm['region'] = sns_message['Region']
    # alarm['instance_id'] = sns_message['Trigger']['Dimensions'][0]['value']
    # alarm['previous_state'] = sns_message['OldStateValue']
    
    # Construct URL
    alarm['url'] = f"https://{alarm['region']}.console.aws.amazon.com/cloudwatch/home?region={alarm['region']}#alarmsV2:alarm/{alarm['name']}"
    
    return alarm

# Forms a Slack message
def handle_alarm(alarm, status):
    # Possible status codes: ALARM, OK, UNKNOWN
    status_text = ":red_circle: Alarm: " if status == "ALARM" else ":large_green_circle: OK: " if status == "OK" else ":white_circle: UNKNOWN: "
    return {
        "type": "home",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": status_text + alarm['name'],
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "_" + alarm['reason'] + "_"
                },
                "block_id": "text1"
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "Account ID: " + alarm['accountid']
                    },
                    {
                        "type": "mrkdwn",
                        "text": "URL: " + alarm['url']
                    }
                ]
            }
        ]
    }

def lambda_handler(event, context):
    try:
        sns_message = event['Records'][0]['Sns']['Message']
    except KeyError:
        print("Error: 'Message' key not found in SNS event. Is this a CloudWatch alarm?")
        return
    
    alarm = get_alarm_attributes(sns_message)

    msg = str()
    msg = handle_alarm(alarm,alarm['state'])

    encoded_msg = json.dumps(msg).encode("utf-8")
    resp = http.request("POST", slack_url, body=encoded_msg)
    
    #DEBUG - uncomment to send output to CloudWatch logs
    #print(
    #    {
    #        "message": msg,
    #        "status_code": resp.status,
    #        "response": resp.data,
    #    }
    #)
