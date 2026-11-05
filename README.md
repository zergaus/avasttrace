# AvastTrace

**Avast Behavior Shield 탐지와 Windows 프로세스 실행 기록을 연결해 조사하기 위한 로컬 진단 도구.**  
*Local Windows diagnostics for correlating Avast alerts with process-start evidence.*

> **상태: Experimental / 실제 Avast 차단 E2E 미검증.** Windows GitHub CI에서 기본 수집·4단계 실행 체인 재구성·설치·보고서 생성을 확인했습니다. 내부 탐지 규칙·정확한 원인 확정 기능은 제공하지 않습니다.

## 왜 만들었나요?

일부 Windows PC에서 Avast가 정상 Windows 구성 요소인 `C:\Windows\System32\conhost.exe`를 **`IDP.Generic` / `Behavior Shield`**로 반복 차단하는 현상이 관찰됐습니다. 개발자 도구, PowerShell, WSL, SSH 또는 백그라운드 프로세스가 실행되는 환경에서 이런 알림이 발생하면 **어떤 명령과 어떤 부모 프로세스 직후에 경고가 나타났는지** 조사하기가 어렵습니다.

AvastTrace는 보호 기능을 비활성화하거나 파일을 예외 처리하지 않고, 다음 자료를 같은 시간 범위에서 수집해 원인 후보를 좁히도록 만들었습니다.

1. Windows 프로세스 생성 이벤트의 **원시 발생 시각**, PID·부모 PID (WMI `Win32_ProcessStartTrace`)
2. Windows Security 이벤트 **4688** (활성화된 경우 명령줄 포함)
3. Avast 로그/보고서의 새 탐지 관련 문자열
4. `conhost.exe` 파일의 SHA-256 및 디지털 서명 상태

**주요 목적: 어떤 실행 명령이 Avast 경고 시각 주변에서 실행됐는지 개발자가 바로 확인하도록 돕는 것.** 4688 명령줄과 부모 PID를 사건별 실행 체인으로 복원합니다. [사건 중심 진단 사용법](docs/INCIDENT_INVESTIGATION.md)을 먼저 확인하세요.

**시간상 인접한 프로세스는 원인 '후보'일 뿐입니다.** 독립적인 재현과 추가 증거 없이는 악성코드·오탐·특정 도구의 원인 관계를 단정하지 않습니다.

## 설치 (Windows PowerShell 5.1)

Windows 10/11 PC에서 **PowerShell을 실행하고** 아래 명령을 입력합니다. 파일을 다운로드한 뒤 실행하기 때문에, `iwr | iex` 형태의 원격 코드 직접 실행은 사용하지 않습니다.

```powershell
$ErrorActionPreference = 'Stop'
$refUri = 'https://api.github.com/repos/zergaus/avasttrace/git/ref/heads/main?nocache=' + [guid]::NewGuid().ToString('N')
$revision = (Invoke-RestMethod $refUri -Headers @{ 'User-Agent' = 'AvastTrace-Installer'; 'Cache-Control' = 'no-cache' }).object.sha
if ($revision -notmatch '^[0-9a-f]{40}$') { throw 'GitHub revision lookup failed' }
$installer = Join-Path $env:TEMP 'AvastTrace-Install.ps1'
Invoke-WebRequest "https://raw.githubusercontent.com/zergaus/avasttrace/$revision/Install.ps1" -OutFile $installer -UseBasicParsing -ErrorAction Stop
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installer
if ($LASTEXITCODE -ne 0) { throw 'AvastTrace installation failed' }
```

- 설치 스크립트는 먼저 GitHub에서 최신 커밋 SHA를 조회한 뒤 **해당 커밋에 고정된** `AvastTrace.ps1`과 `SHA256SUMS.txt`를 HTTPS로 내려받아 **SHA-256 일치 여부를 확인한 뒤** 설치합니다.
- 설치 과정에서 관리자 권한(UAC)을 요청합니다. 예약 작업 `\AvastTrace\AvastTrace-Collector`를 **SYSTEM / 부팅 시 실행**으로 등록하고 즉시 시작합니다.
- 데이터는 **해당 PC 내부** `C:\ProgramData\AvastTrace\`에만 저장합니다. **원격 서버·GitHub로 전송하지 않습니다.**
- **기본 설치는 Windows 감사 정책을 변경하지 않습니다.** 더 정확한 명령줄 증거가 필요할 때만 아래 선택적 설정을 적용합니다.
- `main` 브랜치는 업데이트될 수 있습니다. 운영환경에서는 실행 전에 [소스](AvastTrace.ps1)와 [설치 스크립트](Install.ps1)를 검토하세요. **매니페스트와 코드가 같은 저장소에서 제공되므로 SHA-256 검사는 단독으로 게시자 신뢰를 보장하지는 않습니다.**

### 권장: 이벤트 소실 방지용 4688 로컬 보존 (명시적 선택)

Windows 보안 이벤트 로그(Security.evtx)는 기록량에 따라 오래된 4688 실행 기록이 덮어써질 수 있습니다. **AvastTrace v1.2.0부터** 명령줄 증거를 별도의 관리자 전용 JSONL 파일에 보존하는 기능을 추가했습니다. **기본 설치에서는 꺼져 있습니다.**

최초 설치에서 Windows 4688 감사와 로컬 보존을 모두 사용하려면:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$env:TEMP\AvastTrace-Install.ps1" -EnableAudit -Preserve4688
```

이미 감사가 켜진 PC에서 기존 수집기를 교체하면서 보존만 추가하려면:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$env:TEMP\AvastTrace-Install.ps1" -Preserve4688
```

- 보존 파일: `C:\ProgramData\AvastTrace\security4688-YYYYMMDD.jsonl`, 마지막 기록 커서: `security4688-cursor.json`, 선택 상태: `config.json`.
- 크기 제한: **총 512 MiB**. 초과하면 기존 증거를 임의로 지우지 않고 **추가 보존을 중단하고 오류를 기록**합니다. 디스크 사용량을 확인해야 합니다.
- 최초 활성화 시 최근 약 10분간 Security 이벤트부터 보존을 시도합니다. 이미 덮어쓴 기록은 복구할 수 없습니다.
- **보안:** 모든 실행 명령줄이 평문으로 저장될 수 있고 비밀번호·토큰이 포함될 수 있습니다. 관리자/SYSTEM 이외의 접근을 허용하지 않도록 설계했으며, 공개 저장소나 이슈에 원본 로그를 업로드하면 안 됩니다.
- 설치기의 `-Preserve4688` 선택은 재설치해도 유지되며, 수집기 예약 작업을 제거하면 보존도 중단됩니다. 기존 보존 파일과 감사 정책은 자동 삭제하지 않습니다.

사건 분석 시 보존본이 있으면 Security.evtx 기록이 순환 삭제된 후에도 `ProcessCorrelation`의 실행 체인에 이용합니다. **보존을 켜는 시점 이전에 소실된 명령은 재구성할 수 없습니다.**

### 선택: Windows 4688 명령줄 감사 켜기

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$env:TEMP\AvastTrace-Install.ps1" -EnableAudit
```

**주의:** 이 옵션은 Windows의 프로세스 생성 감사를 켜고 실행 명령줄을 Windows 보안 이벤트 로그에 **평문으로 기록**할 수 있습니다. 명령줄에 비밀번호·API 토큰·민감한 경로가 포함될 수 있습니다. 회사·관리형 장비에서는 적용 전 조직 보안 정책을 확인하세요. 이전 설정은 `audit-before-*.json`에 남기며, 제거 시 이 감사 설정을 **자동 복구하지 않습니다**.

## 사용법

다음 명령은 설치된 스크립트를 사용합니다. **관리자 PowerShell**에서 실행하면 편리합니다.

**상태 확인**

```powershell
powershell.exe -NoProfile -File "C:\ProgramData\AvastTrace\AvastTrace.ps1" -Mode Status
```

`Task: Running`, 최근 `heartbeat.txt`, `process-*.jsonl`의 실제 생성·갱신 여부를 확인합니다. 상태 메시지만으로 데이터 수집 품질을 확정하지 마세요.

**방금 발생한 탐지의 전후 기록 캡처**

```powershell
powershell.exe -NoProfile -File "C:\ProgramData\AvastTrace\AvastTrace.ps1" -Mode Capture
```

**정해진 시각을 기준으로 조사 (PC 로컬 시간)**

Avast 팝업을 본 시각과 팝업에 표시된 실행 파일명을 입력합니다. 실제 탐지 시각과 다를 수 있습니다.

```powershell
powershell.exe -NoProfile -File "C:\ProgramData\AvastTrace\AvastTrace.ps1" -Mode Capture -At "2026-11-05 07:01:03" -TargetImage conhost.exe
```

탐지 시간 기준 **전후 3분**의 기록을 연결합니다. 현재 시각으로 실행한 `Capture`는 실제 팝업이 발생한 시각이 아닌 **명령 실행 시각**을 중심으로 분석하므로, 늦게 실행했다면 반드시 `-At`으로 시간을 지정하세요.

**제거 (수집 기록 유지)**

```powershell
powershell.exe -NoProfile -File "C:\ProgramData\AvastTrace\AvastTrace.ps1" -Mode Uninstall
```

예약 작업을 제거합니다. 보존된 진단 기록과 `-EnableAudit`에서 바꾼 시스템 감사 정책은 자동 삭제·복원하지 않습니다.

## 데이터와 보안

| 파일 | 의미 |
| --- | --- |
| `security4688-YYYYMMDD.jsonl` | 선택한 경우 별도 보존되는 Windows 4688 명령줄·부모 PID 등 (민감 정보 포함) |
| `process-YYYYMMDD.jsonl` | WMI 프로세스 시작 시각(`At`), 수신 시각(`ObservedAt`), 큐 지연, PID·부모 PID (명령줄은 4688 활용) |
| `signals-YYYYMMDD.jsonl` | 변경된 Avast 텍스트 로그의 탐지 키워드 |
| `ProcessCorrelation` (incident JSON) | 4688 기반 주변 프로세스 실행 명령 및 부모 실행 체인 (인과관계 아님) |
| `incident-*.json` | 관련 이벤트·Avast 문자열·실행 프로세스의 조사 자료 |
| `incident-*.summary.txt` | 사람이 읽는 요약 |
| `errors-YYYYMMDD.jsonl` | 수집 오류 |
| `heartbeat.txt` | 수집기 주기적 생존 기록 |
| `audit-before-*.json` | 감사 변경 전 정보 (`-EnableAudit` 사용 시) |

- 로그와 보고서에 **토큰·비밀번호·사용자 이름·명령줄**이 포함될 수 있습니다. **GitHub Issue/PR에 원본 로그를 게시하지 마세요.** 필요한 범위만 검토 후 비식별화해서 공유하세요.
- 로컬 수집 폴더는 관리자와 SYSTEM으로 제한하도록 설계했습니다. 실제 ACL은 설치 후 운영체제에서 확인해야 합니다.
- 로그 보관기간과 최대 디스크 사용량은 **자동 제한하지 않습니다**. 장기간 사용 시 수집 크기를 점검하세요.
- Windows 명령줄 감사가 이전에 꺼져 있었다면 **과거 실행 명령을 소급 복구할 수 없습니다**.
- 오래된 수집기에는 WMI 이벤트 수신시각을 실제 발생 시각으로 잘못 기록한 문제가 있습니다. 최신판은 `At`에 원래 이벤트 시각, `ObservedAt`에 수신시각을 별도로 남깁니다. 4688과 대조할 때는 **이벤트 발생 시각**을 사용하세요.
- 감사 미활성 상태에서는 WMI만으로 전체 실행 명령줄을 수집하지 않습니다. 최신판은 성능 및 PID 재사용 위험 때문에 WMI 핫패스에서 실시간 프로세스 추가 조회를 수행하지 않습니다.
- PowerShell·WSL·tmux **프로세스 내부에서 실행된 모든 명령**을 복원하는 쉘 기록기는 아닙니다.
- Avast 내부 Behavior Shield 판정 규칙, 차단 대상 전체 호출 스택, 숨겨진 Avast 기록까지 확인할 수는 없습니다.
- Avast 보호/격리/예외를 수정하지 않으며 테스트 목적으로 의심스러운 명령을 재실행하지 않습니다.

## 구성

- [`AvastTrace.ps1`](AvastTrace.ps1) — 진단 수집기
- [`Install.ps1`](Install.ps1) — 외부 다운로드 및 검증 후 설치
- [`SHA256SUMS.txt`](SHA256SUMS.txt) — 배포 파일 무결성 체크섬
- [`LICENSE`](LICENSE) — MIT 라이선스

## 검증 범위

- **수행:** PowerShell 5.1 구문 분석, SHA-256 검사, 합성 4단계 부모·자식 4688 체인 복원, 합성 Avast 탐지 보고서 생성, Windows CI 설치·예약 작업 등록 검증, GitHub 업로드 및 재조회
- **미수행:** 실제 Windows 10/11 + Avast에서 WMI 수집, 예약 작업 실행, 관리자 UAC 동작, 4688 활성화·복구, 실제 IDP.Generic 탐지 E2E
- **권고:** 첫 장비에서 비관리자 설치 상태 → `Status` → 테스트 프로세스 관찰 → `Capture` → `Uninstall` 순으로 확인하고 나머지 장비에 적용

## 공식 참고

- [Microsoft: Event 4688 process creation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688)
- [Microsoft: Windows 명령줄 감사와 민감 정보](https://support.microsoft.com/ko-kr/servicing/os/windows/2015/02/microsoft-security-advisory-update-to-improve-windows-command-line-auditing-february-10-2015)
- [Avast: 스캔 로그 위치](https://support.avast.com/article/Use-Antivirus-Geek-settings)
- [Avast Business: 로그 위치](https://businesshelp.avast.com/Content/Products/General_Help/LogLocations/BaseAntivirusLogs.htm)

---

### English summary

AvastTrace is an experimental, local-only PowerShell utility for investigating repeated Avast Behavior Shield / IDP.Generic alerts by correlating Avast text logs, Windows WMI process starts and optional Security event 4688 command lines. It does **not** disable antivirus protection, label a process as malicious, prove causal attribution or upload collected data. Run the HTTPS download/install commands above from Windows PowerShell; installation requires elevation. The optional `-EnableAudit` modifies Windows audit policy and may log credentials in plaintext command lines. Logs are sensitive, stay on the PC and should never be published unredacted. **Windows + Avast end-to-end validation is still pending.**
