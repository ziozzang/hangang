# 압축 폭탄 회귀 시험 자료

두 파일 모두 0 바이트의 반복을 압축한 무해한 시험 자료이다. 제품이 압축 해제 전에 거절하는지 확인하는 데만 사용하며 시험에서는 해제하지 않는다.

| 파일 | 압축 크기 | 원래 크기 | SHA-256 |
|---|---:|---:|---|
| one-mib-zeroes.gz | 1051 바이트 | 1,048,576 바이트 | 9867d767f7edb330f1aa4200fa20aa74cc316e72201b7513ce4db3ccc08cf2d7 |
| one-gib-zeroes.br | 809 바이트 | 1,073,741,824 바이트 | e72e4614de68bb7fd209110bf757203a085da0f7adadd5b05e9c2401fbba502e |

gzip은 Python 표준 라이브러리의 gzip.compress(bytes(1 << 20), mtime=0)로 만들었다. Brotli는 로컬 libbrotlienc의 스트리밍 인코더(quality=5, lgwin=24, lgblock=24)에 1 MiB의 0 바이트를 1024번 넣어 만들었다. 1 GiB 배열을 만들거나 C Brotli 해제기를 실행하지 않았다. 두 자료는 실행 코드·사용자 자료·비밀값을 포함하지 않는다.
