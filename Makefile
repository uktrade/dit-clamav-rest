SHELL := /bin/bash
APPLICATION_NAME="DIT CLAMAV REST"

# Colour coding for output
COLOUR_NONE=\033[0m
COLOUR_GREEN=\033[32;01m
COLOUR_YELLOW=\033[33;01m
COLOUR_RED='\033[0;31m'

help:
	@echo -e "$(COLOUR_GREEN)|--- $(APPLICATION_NAME) ---|$(COLOUR_NONE)"
	@echo -e "$(COLOUR_YELLOW)make build$(COLOUR_NONE) : Run docker-compose build"
	@echo -e "$(COLOUR_YELLOW)make up$(COLOUR_NONE) : Run docker-compose up"
	@echo -e "$(COLOUR_YELLOW)make down$(COLOUR_NONE) : Run docker-compose down"
	@echo -e "$(COLOUR_YELLOW)make test$(COLOUR_NONE) : Run tests"

test:
	docker-compose run --rm -e APP_CONFIG=config.TestConfig clamav_rest python -m unittest tests.py

up:
	docker-compose up -d --build

down:
	docker-compose down

build:
	docker-compose build
