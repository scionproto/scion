#!/bin/bash
set -e

REPOS="dispatcher border dispatcher_go sig beacon cert path sciond tester sig_acceptance scion_ci"
# Generated with aws ecr get-lifecycle-policy --repository-name ${Existing repo with rule}
LIFECYCLE_POLICY_TEXT='{"rules":[{"rulePriority":1,"description":"Delete_after_one_week","selection":{"tagStatus":"any","countType":"sinceImagePushed","countUnit":"days","countNumber":7},"action":{"type":"expire"}}]}'

for repo in $REPOS; do
    echo "Creating $repo and attaching delete policy to it"
    aws ecr create-repository --repository-name $repo
    aws ecr put-lifecycle-policy --repository-name $repo --lifecycle-policy-text "$LIFECYCLE_POLICY_TEXT"
done
