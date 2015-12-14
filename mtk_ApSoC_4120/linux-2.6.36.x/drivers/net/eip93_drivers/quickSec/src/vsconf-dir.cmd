@echo off
echo processing %1
pushd "%~1"
for %%t in (*_project.t) do "%~2" -cr "%~3" "%%t" "%~4\project.t"
for %%t in (*_workspace.t) do "%~2" -cr "%~3" "%%t" "%~4\workspace.t"
popd
