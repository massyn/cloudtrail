import boto3
import json
import datetime

def read_cloudtrail_events(StartTime,OutputPath):
    
    IgnoreEvents = ['UpdateInstanceAssociationStatus','UpdateInstanceInformation','UpdateInstanceCustomHealthStatus','AssumeRole','AssumeRoleWithSAML']

    latest = None
    count = 0
    
    for e in boto3.client('cloudtrail').get_paginator('lookup_events',
    ).paginate(StartTime = StartTime,LookupAttributes=[
        {
            'AttributeKey': "ReadOnly",
            'AttributeValue': "false"
        }
    ]):
        for event in e.get('Events'):
            CloudTrailEvent = json.loads(event['CloudTrailEvent'])
            eventName = CloudTrailEvent['eventName']
            recipientAccountId = CloudTrailEvent['recipientAccountId']
            eventID = CloudTrailEvent['eventID']
            eventTime = datetime.datetime.strptime(CloudTrailEvent['eventTime'], "%Y-%m-%dT%H:%M:%SZ")
            eventTimeStamp = eventTime.strftime('%Y%m%d-%H%M%S')

            if not eventName in IgnoreEvents:
                # == save the file
                fileName = f"{OutputPath}/{recipientAccountId}-{eventTimeStamp}-{eventName}-{eventID}.json"
                with open(fileName,"wt") as q:
                    q.write(json.dumps(CloudTrailEvent,indent=4))

            # == determine the latest time
            if latest == None:
                latest = eventTime
            if latest < eventTime:
                latest = eventTime

            # == count the number of events
            count += 1

    print(f"Total of {count} events...")
    return latest

def get_caller_identity():
    return boto3.client('sts').get_caller_identity()['Account']

def main():

    
    with open('data.json','rt') as q:
        data = json.load(q)

    a = get_caller_identity()
    print(f"AccountID = {a}")
    if not a in data:
        data[a] = { 'latest' : None}

    latest = read_cloudtrail_events(data[a]['latest'],'../../cloudtrail')

    data[a]['latest'] = latest.strftime('%Y-%m-%d %H:%M:%S')

    with open('data.json','wt') as q:
        q.write(json.dumps(data,indent=4))

main()