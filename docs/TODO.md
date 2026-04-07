# TODO

## Current

- Debian 또는 Ubuntu 환경에서 `./scripts/build_deb.sh`를 실제 실행해 `.deb` 생성 여부를 확인한다.
- 대상 배포판에서 `python3-fastapi`, `python3-uvicorn`, `python3-aiohttp`, `python3-yaml` 패키지명이 정확히 일치하는지 확인한다.
- 필요하면 GitHub Actions 또는 별도 빌더에서 자동 패키지 빌드와 APT 게시 파이프라인을 추가한다.
- 경고 제거 반영본으로 재빌드해서 `dh_python3` 및 duplicate conffile 경고가 사라졌는지 확인한다.
