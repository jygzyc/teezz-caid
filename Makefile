
.PHONY: init run test

DEVICE_ID ?= AAAAAAAAAAAAAA
# LIB_PATH ?= /vendor/lib64/libMcClient.so # MTK
LIB_PATH ?= vendor/lib64/libQSEEComAPI.so # QSEE

help: ## Show this help
	@egrep -h '\s##\s' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

init: ## Init tools
	@bash dist/tool_init.sh

run:  ## Run command
	@bash dist/run.sh ${LIB_PATH} ${DEVICE_ID}

test: ## Run test
	@bash dist/test.sh
	

