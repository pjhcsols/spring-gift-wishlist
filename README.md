# spring-gift-wishlist

- [1단계 - 유효성 검사 및 예외 처리](#1단계---유효성-검사-및-예외-처리)
  - [기능 요구 사항 정리](#구현-기능-목록)
  - [구현 기능 목록](#구현-기능-목록)

---

# 1단계 - 유효성 검사 및 예외 처리

## 기능 요구 사항 정리

- 상품을 추가하거나 수정하는 경우, 클라이언트로부터 잘못된 값이 전달될 수 있다. 잘못된 값이 전달되면 클라이언트가 어떤 부분이 왜 잘못되었는지 인지할 수 있도록 응답을 제공한다.

    - 상품 이름은 공백을 포함하여 최대 15자까지 입력할 수 있다.
    - 특수 문자 
      - 가능: ( ), [ ], +, -, &, /, _
      - 그 외 특수 문자 사용 불가
    - "카카오"가 포함된 문구는 담당 MD와 협의한 경우에만 사용할 수 있다.


## 구현 기능 목록

- 상품 이름 유효성 검사
  - 상품 이름의 길이가 15자를 초과하는지 확인
  - 상품 이름에 사용 가능한 특수 문자를 제외한 특수 문자가 있는지 확인
  - "카카오"가 포함되어 있을 경우 담당 MD와 협의한 경우에만 사용할 수 있다는 메시지 출력


- 상품 추가 및 수정에서 잘못된 요청에 대한 응답 제공
  - 상품 이름의 유효성 검사에서 잘못된 부분을 응답 내용에 반영

---