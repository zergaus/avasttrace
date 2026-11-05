# 사건 중심 개발자 진단 (Incident investigation)

> AvastTrace is an experimental local-only tool. It helps developers reconstruct **which process commands ran near a reported Avast alert**, not prove exactly which code Avast blocked or why an internal heuristic fired.

## 왜 필요한가?

개발자가 직접 만든 프로그램이 PowerShell, CMD, Node.js, WSL 등 외부 프로세스를 반복 실행할 때 Avast Behavior Shield가 `IDP.Generic`이나 `conhost.exe` 같은 이름으로 경고를 띄울 수 있습니다. **자주 실행된 프로세스**와 **실제 차단된 프로세스**는 다릅니다. 원인 후보를 찾으려면 **탐지 시각·대상 파일·실행 명령·부모 프로세스**를 서로 연결해야 합니다.

AvastTrace는 보안 제품을 끄거나 예외를 추가하지 않습니다. 감사 이벤트 4688의 기록이 남아 있는 범위에서 명령줄을 연결하고, 확정할 수 없는 증거에는 UNKNOWN이라고 표시합니다.

## 사고 기록 1건 분석

관리자 PowerShell에서, 팝업을 **실제로 본 시각**을 `-At`에 넣습니다.

~~~powershell
powershell.exe -NoProfile -File "C:\ProgramData\AvastTrace\AvastTrace.ps1" -Mode Capture -At "2026-11-05 09:06:06" -TargetImage conhost.exe
~~~

- `-TargetImage`: Avast 팝업이 표시한 **실행 파일명** (예: `conhost.exe`, `powershell.exe`, `myapp.exe`). 생략하면 관찰 시각 **±5초**의 프로세스 시작 기록 최대 40건을 보여줍니다.
- 지정한 이미지가 있으면 관찰 시각 **±30초** 안의 해당 이미지 시작 기록 최대 40건에 대해 조상 실행 체인을 복원합니다.
- `-At`을 생략하면 실행 시각을 **임시 관찰 시각**으로 삼으므로, 과거 사건에는 반드시 입력하세요.

만약 Avast 자체에서 **진짜 탐지 시각이 별도로 검증**됐다면 다음처럼 두 시각을 구분하세요.

~~~powershell
powershell.exe -NoProfile -File "C:\ProgramData\AvastTrace\AvastTrace.ps1" -Mode Capture -At "2026-11-05 09:08:00" -DetectionAt "2026-11-05 09:06:06" -TargetImage conhost.exe
~~~

`-At`은 **팝업 관찰 시각**, `-DetectionAt`은 사용자가 별도로 확인한 **탐지 시각**입니다. 탐지 시각이 있으면 해당 시간을 기준으로 사건 창을 만듭니다. 모르겠으면 **절대로 추정해서 채우지 마세요**.

## 산출물 읽기

`C:\ProgramData\AvastTrace\incident-*.summary.txt`에는 **CLOSEST EXECUTION CHAINS** 항목이 있고, 원본 JSON의 `ProcessCorrelation.Candidates[].Chain`에는 실제 4688 이벤트의 `Time`, `Process`, `PID`, `Parent`, `ParentPID`, `CommandLine`이 포함됩니다. 부모 이벤트가 이전에 생성되었거나 로깅되지 않았다면 `UnresolvedParent`에 이름만 표시하고 **실행 명령은 만들어 넣지 않습니다**.

| 필드 | 정확한 의미 |
| --- | --- |
| `PopupObservedAt` | 사용자가 보고한 팝업 관찰 시각. 자동 로그 감지에서는 `null` |
| `AvastLogAppendObservedAt` | Avast 텍스트 로그에 변화가 관찰된 시각. 팝업이나 실제 탐지 시각 아님 |
| `AvastDetectionAt` | 별도로 입력한 탐지 시각. 확인되지 않으면 `null` |
| `DetectionTimestampStatus` | `UNKNOWN` 또는 사용자가 입력한 미독립검증 값 |
| `ProcessCorrelation` | 실행 시각과 부모 PID로 연결한 Windows 4688 실행 체인. 원인 확정 **아님** |
| `AvastKeywordMatches` | 최근 Avast 로그 텍스트 일부. 시간 정보가 검증되지 않은 문구는 `UNKNOWN_UNPARSED_RAW_LINE` |

**출력 예시 (합성 데이터이며 실제 탐지 원인 아님):**

~~~text
DemoController.exe
  -> cmd.exe /c npm.cmd run runtime:status
     -> node.exe scripts/runtime/runtime-manager.js status --json
        -> conhost.exe
Interpretation: PROCESS_START_PROXIMITY_AND_4688_ANCESTRY_ONLY_NOT_AVAST_CAUSALITY
~~~

이 기록을 통해 개발자는 자신의 소스 코드에서 `runtime:status`, `Process.Start` 등 **실제 호출 명령을 검색할 근거**를 얻을 수 있습니다. 4688만으로 정확한 소스 파일·줄 번호를 복원할 수는 없습니다.

## 자동 캡처의 조건 및 한계

AvastTrace는 지정된 Avast **텍스트 로그에 새로 추가되는 탐지 관련 문자열**을 관찰한 경우 자동 캡처를 시도합니다. Avast가 해당 기록을 텍스트로 남기지 않거나 감시 경로가 다르면 자동 사건이 생성되지 않을 수 있습니다. 로그 텍스트의 기록 추가 시각과 Avast 내부 **실제 탐지 시각은 동일하다고 보장할 수 없습니다**. `AvastKeywordMatches` 250건은 **탐지 250회가 아닙니다**.

Windows 4688 감사가 사전에 활성화되어 있지 않았거나 보안 로그가 덮어쓰기되었으면 과거 명령을 복원할 수 없습니다. 프로세스 생성 전에 차단하면 4688 자체가 남지 않을 수도 있습니다. 부모 PID가 같더라도 재사용됐을 수 있어 **실행 시각과 부모 실행 파일명**을 함께 대조합니다.

## 보호 및 품질 검증

- Avast, Windows Defender, 방화벽 및 격리 설정을 변경하거나 보호를 끄지 않습니다.
- `-EnableAudit` 옵션은 4688 감사 설정을 바꿉니다. 민감한 명령줄이 **평문으로 로컬 Security 이벤트**에 기록될 수 있으므로 정책 승인 후 사용하세요.
- 수집 파일과 원본 명령줄은 외부로 전송하지 않습니다. **공개 GitHub Issue에 원본 JSON 또는 로그를 게시하지 마세요.**
- 권장 테스트: `powershell.exe -NoProfile -File "C:\ProgramData\AvastTrace\AvastTrace.ps1" -Mode SelfTest`. 합성 4단계 4688 프로세스 체인 및 대상 필터링을 검증합니다. 실제 Avast 내부 탐지 규칙 검증과는 다릅니다.
- 실제 원인 확인에는 탐지 이벤트 식별자/실제 시각 및 통제된 반복 재현이 필요할 수 있습니다. 단순한 시간 근접성은 인과관계 증거가 아닙니다.
