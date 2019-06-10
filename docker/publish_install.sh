#!/bin/ash

set -e

[ -z "$BUCKET_NAME" ] && echo "Need to set BUCKET_NAME" && exit 1;
[ -z "$AWS_REGION" ] && echo "Need to set AWS_REGION" && exit 1;

echo "publish to s3 bucket"
s3pypi --bucket $BUCKET_NAME --force

echo "install from s3 bucket"
PIP3_URL=http://$BUCKET_NAME.s3-website-$AWS_REGION.amazonaws.com/truffleHogWize/
TRUSTED_HOST=$BUCKET_NAME.s3-website-$AWS_REGION.amazonaws.com

pip3 install truffleHogWize==2.0.92.1 -v \
  --extra-index-url $PIP3_URL \
  --trusted-host $TRUSTED_HOST
