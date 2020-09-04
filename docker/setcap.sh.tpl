#!/bin/bash

# Copyright 2017 The Bazel Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Copyright 2020 Anapaya Systems
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This file was initially copied from rules_docker/docker/util/commit.sh.tpl and then adapted,
# see https://github.com/bazelbuild/rules_docker/blob/master/docker/util/commit.sh.tpl

set -e

# Setup tools and load utils
TO_JSON_TOOL="%{to_json_tool}"
source %{util_script}

# Resolve the docker tool path
DOCKER="%{docker_tool_path}"
DOCKER_FLAGS="%{docker_flags}"

if [[ -z "$DOCKER" ]]; then
    echo >&2 "error: docker not found; do you need to manually configure the docker toolchain?"
    exit 1
fi

# Load the image and remember its name
image_id=$(%{image_id_extractor_path} %{image_tar})
$DOCKER $DOCKER_FLAGS load -i %{image_tar}

id=$($DOCKER $DOCKER_FLAGS run -d --entrypoint setcap $image_id %{caps} %{binary})
# Actually wait for the container to finish running its commands
retcode=$($DOCKER $DOCKER_FLAGS wait $id)
# Trigger a failure if the run had a non-zero exit status
if [ $retcode != 0 ]; then
  $DOCKER $DOCKER_FLAGS logs $id && false
fi

reset_cmd $image_id $id %{output_image}
$DOCKER $DOCKER_FLAGS save %{output_image} -o %{output_tar}
$DOCKER $DOCKER_FLAGS rm $id
