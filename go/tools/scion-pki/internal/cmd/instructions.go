// Copyright 2020 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

const (
	bashInstr = `
sudo mv /tmp/scion-pki/scion_pki_bash /etc/bash_completion.d
source ~/.bashrc
`

	zshInstr = `
mkdir -p ~/.zsh/completion
mv /tmp/scion-pki/_scion-pki ~/.zsh/completion
cat <<EOF >> ~/.zshrc
fpath=(~/.zsh/completion \$fpath)
autoload -U compinit
compinit
zstyle ':completion:*' menu select=2
EOF
source ~/.zshrc
`
)
