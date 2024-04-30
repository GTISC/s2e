#!/bin/bash

{% include 'common-run.sh.tpl' %}

s2e run -n {{ project_name }}

! grep -q "Failed to find nullptr char in string" $S2E_LAST/debug.txt

