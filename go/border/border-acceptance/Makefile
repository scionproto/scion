default:
	@echo "TODO help"

info_fn := info.txt
border-core-ids := core-brA core-brB core-brC
border-ids := brA brB brC brD

${border-core-ids}:
	./setup.sh $@ ${info_fn}
	border-acceptance -borderID "$@" -devInfoFilePath ${info_fn} -keysDirPath br-core-conf/keys
	./teardown.sh

${border-ids}:
	./setup.sh $@ ${info_fn}
	border-acceptance -borderID "$@" -devInfoFilePath ${info_fn} -keysDirPath br-non-core-conf/keys
	./teardown.sh

setup-%:
	./setup.sh $* ${info_fn}

test-core-%:
	border-acceptance -borderID core-$* -devInfoFilePath ${info_fn} -keysDirPath br-core-conf/keys $(EXTRA)

test-%:
	border-acceptance -borderID $* -devInfoFilePath ${info_fn} -keysDirPath br-non-core-conf/keys $(EXTRA)

teardown:
	./teardown.sh

all: ${border-core-ids} ${border-ids}
