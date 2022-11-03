import boto3
import json
import datetime
import os
import jmespath

def read_cloudtrail_events(region,StartTime,OutputPath):
    
    if StartTime == None:
        st = datetime.datetime(2000,1,1,0,0,0)
    else:
        st = StartTime

    IgnoreEvents = ['ConsoleLogin','CredentialVerification','CredentialChallenge','UpdateInstanceAssociationStatus','UpdateInstanceInformation','UpdateInstanceCustomHealthStatus','AssumeRole','AssumeRoleWithSAML']

    latest = None
    count = 0
    
    for e in boto3.client('cloudtrail',region_name = region).get_paginator('lookup_events',
    ).paginate(StartTime = st ,LookupAttributes=[
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

def dumpLogs(outputPath,region):
    try:
        print('Reading existing file...')
        with open('data.json','rt') as q:
            data = json.load(q)
    except:
        print('Start a fresh file...')
        data = {}

    a = get_caller_identity()
    print(f"AccountID = {a}")
    if not a in data:
        data[a] = { 'latest' : {}}

    latest = read_cloudtrail_events(region,data[a]['latest'].get(region),outputPath)

    data[a]['latest'][region] = latest.strftime('%Y-%m-%d %H:%M:%S')

    print('Write the data file...')
    with open('data.json','wt') as q:
        q.write(json.dumps(data,indent=4))

def parseEventLog(data,event):
    def myDB(db,action,leaf,key,data):
        if not leaf in db:
            db[leaf] = []
        new = []

        if action == 'add':
            t = False
            for i in db[leaf]:
                if i[key] == data[key]:
                    t = True
                    new.append(data)
                else:
                    new.append(i)
            if not t:
                new.append(data)
        elif action == 'merge':
            touched = False
            for i in db[leaf]:
                if i[key] == data[key]:
                    for x in data:
                        i[x] = data[x]
                        touched = True
                new.append(i)
            
            if not touched:
                new.append(data)
        elif action == 'delete':
            for i in db[leaf]:
                if i[key] != data[key]:
                    new.append(i)
        else:
            print('UNKNOWN ACTION')
            exit(1)
        
        db[leaf] = new

    cfg = {
        "cloudformation.describe_stack_sets" : [
            {
                "eventName" : "CreateStackInstances",
                "action"    : "add",
                "key"       : "stackSetName",
                "data"      : event['requestParameters']
            },
            {
                "eventName" : "DeleteStackInstances",
                "action"    : "delete",
                "key"       : "stackSetName",
                "data"      : event['requestParameters']
            },
        ],
        "ecs.describe_instances" : [
            {
                "eventName" : "RebootInstances",
                "action"    : "merge",
                "key"       : "instanceId",
                "data"      : jmespath.search('requestParameters.instancesSet.items',event)
            },
            {
                "eventName" : "StartInstances",
                "action"    : "merge",
                "key"       : "instanceId",
                "data"      : jmespath.search('responseElements.instancesSet.items',event)
            },
            {
                "eventName" : "StopInstances",
                "action"    : "merge",
                "key"       : "instanceId",
                "data"      : jmespath.search('responseElements.instancesSet.items',event)
            },
            {
                "eventName" : "RunInstances",
                "action"    : "add",
                "key"       : "instanceId",
                "data"      : jmespath.search('responseElements.instancesSet.items',event)
            },
            {
                "eventName" : "TerminateInstances",
                "action"    : "delete",
                "key"       : "instanceId",
                "data"      : jmespath.search('responseElements.instancesSet.items',event)
            },
            {
                "eventName" : "ModifyInstanceAttribute",
                "action"    : "merge",
                "key"       : "instanceId",
                "data"      : event['requestParameters']
            }
        ],
        "rds.describe_databases" : [
            {
                "eventName" : "CreateDBInstance",
                "action" : "add",
                "key" : "dbiResourceId",
                "data" : event['responseElements'],
            },
            {
                "eventName" : "ModifyDBInstance",
                "action" : "merge",
                "key" : "dbiResourceId",
                "data" : event['responseElements'],
            },
            {
                "eventName" : "DeleteDBInstance",
                "action" : "delete",
                "key" : "dbiResourceId",
                "data" : event['responseElements'],
            }
        ],
        "s3.buckets" : [
            {
                "eventName" : "CreateBucket",
                "action" : "add",
                "key" : "bucketName",
                "data" : event['requestParameters'],
                'debug' : True
            },
            {
                "eventName" : "DeleteBucket",
                "action" : "delete",
                "key" : "bucketName",
                "data" : event['requestParameters']
            }
        ],
        "ssm.describe_instance_information" : [
            {
                "eventName" : "UpdateInstanceInformation",
                "action" : "merge",
                "key" : "instanceId",
                "data" : event['requestParameters'],
            },
            {
                "eventName" : "TerminateInstances",
                "action" : "delete",
                "key" : "instanceId",
                "data" : jmespath.search('responseElements.instancesSet.items',event)
            },

        ],
        "logs.describe_log_streams" : [
            {
                "eventName" : "CreateLogStream",
                "action" : "add",
                "key" : "logGroupName",
                "data" : event['requestParameters'],
            }
        ]
    }

    result = False
    for leaf in cfg:
        for c in cfg[leaf]:
            if c['eventName'] == event['eventName']:
                if not 'data' in c:
                    print(json.dumps(event,indent=4))
                    print(' ************ MISSING DATA PARAMETER ************')
                    exit(0)
                result = True
                if 'debug' in c:
                    print(f"** DEBUG ** Found event {c['eventName']}")
                if type(c['data']) == dict:
                    if 'debug' in c:
                        print(f"** DEBUG ** {c['action']} - {c['key']} - {c['data'][c['key']]}")
                    myDB(data,c['action'],leaf,c['key'],c['data'])
                elif type(c['data']) == list:
                    for cl in c['data']:
                        if 'debug' in c:
                            print(f"** DEBUG ** {c['action']} - {c['key']}  - {cl[c['key']]}")
                        myDB(data,c['action'],leaf,c['key'],cl)

    return result

def readLogs(data,outputPath,accountId):
    pivot = {}
    for f in os.listdir(outputPath):
        with open(f"{outputPath}/{f}",'rt') as j:
            d = json.load(j)

            if d['recipientAccountId'] == accountId and not 'errorCode' in d:

                x = parseEventLog(data,d)
                
                if not x: # and d['eventName'] not in ['SendCommand','AssumeRole','StartInstances','RunInstances','StopInstances','RebootInstances','UpdateInstanceInformation','TerminateInstances','ModifyInstanceAttribute','CreateStackInstances','DeleteStackInstances','CreateDBInstance','ModifyDBInstance','DeleteDBInstance','CreateLogStream']:
                     
                    # == calculate totals
                    if d['eventName'] not in pivot:
                        pivot[d['eventName']] = 0
                    pivot[d['eventName']] += 1

    #print(json.dumps(pivot,indent=4))
    print(json.dumps(data,indent=4))
    
        
dataDir = '../../cloudtrail'


dumpLogs(dataDir,'ap-southeast-2')
dumpLogs(dataDir,'us-east-1')

db = {}
readLogs(db,dataDir,'153977100785')
