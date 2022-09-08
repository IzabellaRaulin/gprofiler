#!/usr/bin/env bash
#sudo rm -rf /tmp/gprofiler_tmp/*
#sudo rm /tmp/gprofiler_tmp/izahelperfile.txt
#docker rm -f gprofiler-debug
docker run --network host --name gprofiler-debug --restart=always -d --pid=host --userns=host -v /tmp/gprofiler_tmp:/tmp/gprofiler_tmp -v /var/run/docker.sock:/var/run/docker.sock --privileged gprofiler-pyperf:0.2 -cu --token="xpXrnM_vFne1LiTn9gK35t2sZgaYEGv8dTcevMECHpI" --service-name="gprofiler-cache-02" -f 99 --perf-mode dwarf
