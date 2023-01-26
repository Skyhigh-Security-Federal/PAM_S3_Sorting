# PAM_S3_Sorting
An AWS lambda python script which integrates with Shyhigh Portable Anti-Malware to decide to move an S3 object to a clean or dirty bucket.

Pre-Reqs:
1) An AWS Account 
2) Four S3 buckets: Clean, Dirty, Investigate, and Logs
3) Portable Anti-Malware running and accessable to Lambda