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

def dumpLogs(outputPath,data,region):
    latest = read_cloudtrail_events(region,data['latest'].get(region),outputPath)
    data['latest'][region] = latest.strftime('%Y-%m-%d %H:%M:%S')

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
                "data" : event['requestParameters']
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

def readLogs(data,outputPath,accountId,IgnoreEvents):
    data['unknownCount'] = {}
    data['TodoList'] = {}

    for f in os.listdir(outputPath):
        with open(f"{outputPath}/{f}",'rt') as j:
            d = json.load(j)

            if d['recipientAccountId'] == accountId and not 'errorCode' in d:
                if not d['eventName'] in IgnoreEvents:
                    x = parseEventLog(data['data'],d)
                    
                    if not x:
                        # == calculate totals
                        if d['eventName'] not in data['unknownCount']:
                            data['unknownCount'][d['eventName']] = 0
                        data['unknownCount'][d['eventName']] += 1

                        # == record a single event that we need to work on
                        if d['eventName'] not in data['TodoList']:
                            data['TodoList'][d['eventName']] = d

    #print(json.dumps(pivot,indent=4))
    #print(json.dumps(data,indent=4))
    
        
dataDir = '../../cloudtrail'
dataFile = '../data.json'

# == read the data
try:
    print('Reading existing file...')
    with open(dataFile,'rt') as q:
        data = json.load(q)
except:
    print('Start a fresh file...')
    data = {}

AccountId = boto3.client('sts').get_caller_identity()['Account']
if not AccountId in data:
    data[AccountId] = {}
if not 'latest' in data[AccountId]:
    data[AccountId]['latest'] = None
if not 'data' in data[AccountId]:
    data[AccountId]['data'] = {}

if not 'unknownCount' in data[AccountId]:
    data[AccountId]['unknownCount'] = {}

IgnoreEvents = ['ConsoleLogin','CredentialVerification','CredentialChallenge','UpdateInstanceAssociationStatus','UpdateInstanceInformation','UpdateInstanceCustomHealthStatus','AssumeRole','AssumeRoleWithSAML']    

dumpLogs(dataDir,data[AccountId],'ap-southeast-2')
dumpLogs(dataDir,data[AccountId],'us-east-1')

readLogs(data[AccountId],dataDir,AccountId,IgnoreEvents)

print('Write the data file...')
with open(dataFile,'wt') as q:
    q.write(json.dumps(data,indent=4))