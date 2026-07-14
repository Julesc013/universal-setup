# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

if(NOT DEFINED USK_ACCEPTANCE_EXE OR NOT EXISTS "${USK_ACCEPTANCE_EXE}")
  message(FATAL_ERROR "usk_live_acceptance executable is unavailable")
endif()

string(SHA256 root_suffix "${USK_TEMP_ROOT}")
string(SUBSTRING "${root_suffix}" 0 12 root_suffix)
if(DEFINED ENV{TEMP})
  set(platform_temp "$ENV{TEMP}")
elseif(DEFINED ENV{TMPDIR})
  set(platform_temp "$ENV{TMPDIR}")
else()
  set(platform_temp "/tmp")
endif()
set(root "${platform_temp}/usk-live-acceptance-test-${root_suffix}")
file(REMOVE_RECURSE "${root}")
file(MAKE_DIRECTORY "${root}")

execute_process(
  COMMAND "${USK_ACCEPTANCE_EXE}"
    --root "${root}"
    --run-id ctest
    --setup-revision aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    --consumer-revision bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    --confirm APPLY
    --test-mode
  RESULT_VARIABLE result
  OUTPUT_VARIABLE output
  ERROR_VARIABLE error
)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "acceptance runner failed (${result}): ${error}")
endif()

set(summary "${root}/ctest/acceptance-summary.json")
if(NOT EXISTS "${summary}")
  message(FATAL_ERROR "acceptance summary was not written")
endif()
file(READ "${summary}" content)
foreach(required
    "automated_findings_complete_pending_operator_verdict"
    "\"operator_verdict\":\"pending\""
    "\"ordinary_live_apply_promoted\":false"
    "\"contains_executable_code\":false"
    "\"name\":\"install_verify\",\"status\":\"pass\""
    "\"name\":\"damage_verify\",\"status\":\"expected_fail\""
    "\"name\":\"cross_volume_move\",\"status\":\"not_attempted_no_second_authorized_volume\""
    "\"name\":\"uninstall_with_foreign_content\",\"status\":\"refused_and_retained\""
    "\"name\":\"clean_uninstall\",\"status\":\"pass\"")
  string(FIND "${content}" "${required}" position)
  if(position EQUAL -1)
    message(FATAL_ERROR "acceptance summary lacks required evidence: ${required}")
  endif()
endforeach()

file(GLOB packets "${root}/ctest/setup-state/evidence/packets/*.json")
list(LENGTH packets packet_count)
if(NOT packet_count EQUAL 4)
  message(FATAL_ERROR "acceptance runner must retain exactly four operation packets, found ${packet_count}")
endif()
file(REMOVE_RECURSE "${root}")
