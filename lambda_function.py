import json
import urllib.parse
import boto3
import base64
import requests
import hashlib


################################################################################
             ###### Only need to update these variables #######
pamURL = "http://HOSTNAME:PORT"
clean_bucket_name = "CLEAN BUCKET NAME" 
dirty_bucket_name = "DIRTY BUCKET NAME"
investigate_bucket_name = "INVESTIGATE BUCKET NAME"
log_bucket_name = "LOGGING BUCKET NAME"
cleanThreshold = 70
dirtyThreshhold = 85
################################################################################

s3 = boto3.client('s3')

def lambda_handler(event, context):
    # Get the bucket and object name from the S3 trigger
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'], encoding='utf-8')
    try:
        # Get the file's content and convert to base64
        origFile = s3.get_object(Bucket=bucket, Key=key)
        base64file = base64.b64encode(origFile['Body'].read() )
        
        
        # String of file location in S3 converted to base64
        ogFileLocation = "https://"+ bucket +".s3.amazonaws.com/" + key
        ogFileLocationBase64 = base64.b64encode(ogFileLocation.encode("ascii"))

        
        # Create payload and headers for REST call
        payloadDict = dict(Body = base64file.decode("utf-8"), SourceURL = ogFileLocationBase64.decode("utf-8"))
        headers = dict(authorization = "Basic YXBpdXNlcjphcGl1c2Vy")
        
        # Make REST call to PAM
        pamResp = requests.post(pamURL+"/GAMScanServer/v1/scans/c2342342/s1231253",data=json.dumps(payloadDict), headers=headers)
 
        # Malware score returned from PAM
        malwareProbablity = pamResp.json()["MalwareProbability"]
        
        
        # Prep all buckets for data movement
        s3move = boto3.resource('s3')
        source_obj = {
            'Bucket': bucket,
            'Key': key
        }
        clean_bucket = s3move.Bucket(clean_bucket_name)
        dirty_bucket = s3move.Bucket(dirty_bucket_name)
        investigate_bucket = s3move.Bucket(investigate_bucket_name)
        orig_bucket = s3move.Bucket(bucket)
        log_bucket = s3move.Bucket(log_bucket_name)
        
        
        # Populating Log Data
        eventTime = event['Records'][0]["eventTime"]
        accountID = boto3.client("sts").get_caller_identity()["Account"]
        username = boto3.client("sts").get_caller_identity()["UserId"]
        dataType = origFile['ContentType']
        sourceFileName = key
        status = "Scanning"
        suspiciousFileName = key
        hash = hashlib.sha256(origFile['Body'].read()).hexdigest()
        malwareConfidenceScore = malwareProbablity
        
        # File is clean
        if malwareProbablity < cleanThreshold:
            clean_bucket.copy(source_obj,key) # Move file to clean bucket
            s3move.Object(bucket, key).delete() # Delete original file in Stage
            
            # Send log data to log bucket
            logData = dict(EventTime = eventTime, AccountID = accountID, Username = username, Datatype = dataType, SourceFileName = sourceFileName, Status = "Clean", SuspiciousFileName = suspiciousFileName, FileHash = hash, MalwareConfidenceScore = malwareConfidenceScore)
            s3.put_object(Body = json.dumps(logData), Bucket = log_bucket_name, Key = eventTime + ".txt")
            
        # File needs more investigation
        elif malwareProbablity < dirtyThreshhold:
            investigate_bucket_bucket.copy(source_obj,key) # Move file to investigate bucket
            s3move.Object(bucket, key).delete() # Delete original file in Stage
            
            # Send log data to log bucket
            logData = dict(EventTime = eventTime, AccountID = accountID, Username = username, Datatype = dataType, SourceFileName = sourceFileName, Status = "Investigate", SuspiciousFileName = suspiciousFileName, FileHash = hash, MalwareConfidenceScore = malwareConfidenceScore)
            s3.put_object(Body = json.dumps(logData), Bucket = log_bucket_name, Key = eventTime + ".txt")
        
        # File is dirty
        else:
            print("Move file to dirty")
            dirty_bucket.copy(source_obj,key) # Move file to dirty bucket
            s3move.Object(bucket, key).delete() # Delete original file in Stage
            
            # Send log data to log bucket
            logData = dict(EventTime = eventTime, AccountID = accountID, Username = username, Datatype = dataType, SourceFileName = sourceFileName, Status = "Dirty", SuspiciousFileName = suspiciousFileName, FileHash = hash, MalwareConfidenceScore = malwareConfidenceScore)
            s3.put_object(Body = json.dumps(logData), Bucket = log_bucket_name, Key = eventTime + ".txt")
        
    except Exception as e:
        print(e)
        print('Error getting object {} from bucket {}. Make sure they exist and your bucket is in the same region as this function.'.format(key, bucket))
        raise e
