#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob

srcdir=$(dirname "$(readlink -f "$0")")

function usage {
  echo "Usage: $0 cmdfile outdir"
  echo "Runs command listed in cmdfile and writes timing results to directory outdir."
  echo
  echo "Lines in cmdfile should have format:"
  echo "  identifier numruns command [args ...]"
  echo
  echo "To run a background process, add a line"
  echo "  BG identifier command [args ...]"
  echo "followed later by a line"
  echo "  KILL identifier"
  echo
  echo "The outdir directory will contain files named like"
  echo "  identifier_run.txt"
  echo "with output for that command and that run index."
  echo
  echo "The first line of each such file will have the (total) CPU time"
  echo "and wall time, in seconds, space-separated."
  [[ $# -eq 1 ]] && exit $1
}

# written to the end of every output file to signal completion
finishline="FINISH"

[[ $# -eq 2 ]] || usage 1

cmdfile=$1
[[ -r $cmdfile ]] || usage 2

outdir=$2
if [[ -e $outdir && ! -d $outdir ]]; then
  usage 3
fi

mkdir -pv "$outdir"

tmpdir=$(mktemp -d --tmpdir timeruns.XXXXXXX)
tmp_stdout="$tmpdir/temp_stdout"
tmp_stderr="$tmpdir/temp_stderr"
tmp_time1="$tmpdir/temp_time1"
tmp_time2="$tmpdir/temp_time2"
tmp_bgout="$tmpdir/temp_bgout"
function cleanup {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

declare -A bgpids
unset bgout

exec 4<"$cmdfile"
while read -u4 ident numruns cmd; do
  if [[ $ident = "BG" ]]; then
    bgid=$numruns
    echo "Starting background process $bgid"
    bgout="$tmpdir/bg-$bgid.out"
    $cmd >"$bgout" 2>&1 &
    bgpids["$bgid"]=$!
    sleep 1
  elif [[ $ident = "KILL" ]]; then
    bgid=$numruns
    echo "Killing background process $bgid"
    kill "${bgpids["$bgid"]}"
    unset "bgpids[$bgid]"
    rm -f "$bgout"
    unset "bgout"
  else
    if [[ -z $cmd ]]; then
      echo "ERROR: invalid cmdfile line: $ident $numruns $cmd"
      exit 1
    fi
    for (( i = 1; i <= numruns; i++ )); do
      outfile="$outdir/${ident}_$i.txt"
      if [[ -e $outfile ]]; then
        if [[ $(tail -1l "$outfile") = $finishline ]]; then
          continue
        fi
      fi
      if [[ -v "bgout" ]]; then
        tail -c0 -f "$bgout" >"$tmp_bgout" &
        tailer=$!
      fi
      echo "running $ident ($i of $numruns)"
      set +e
      /usr/bin/time --quiet -f '%e %S %U' -o "$tmp_time1" /usr/bin/time -v -o "$tmp_time2" $cmd >"$tmp_stdout" 2>"$tmp_stderr"
      ecode=$?
      set -e
      if [[ -v "bgout" ]]; then
        kill -INT "$tailer"
      fi
      exec 5<"$tmp_time1"
      read -u5 wall user sys
      exec 5<&-
      cpu=$(bc -l <<<"$user + $sys")
      (
        echo "$wall $cpu"
        echo
        echo "Verbose time output:"
        cat "$tmp_time2"
        if [[ -s $tmp_stdout ]]; then
          echo
          echo "stdout:"
          cat "$tmp_stdout"
        fi
        if [[ -s $tmp_stderr ]]; then
          echo
          echo "stderr:"
          cat "$tmp_stderr"
        fi
        if [[ -s $tmp_bgout ]]; then
          echo
          echo "background output:"
          cat "$tmp_bgout"
          rm -f "$tmp_bgout"
        fi
        echo
        if [[ $ecode -eq 0 ]]; then
          echo "$finishline"
        else
          echo "EXIT CODE $ecode"
        fi
      ) >"$outfile"
    done
    echo "COMPLETED $numruns runs for $ident"
  fi
done
exec 4<&-

for bgid in "${!bgpids[@]}"; do
  echo "Killing background process $bgid"
  kill "${bgpids["$bgid"]}"
done

echo "ALL DONE"

:
