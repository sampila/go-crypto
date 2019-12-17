package gocrypto

import(
  "testing"
  "github.com/stretchr/testify/assert"
)

func TestHashPassword(t *testing.T){
  hash, err := HashPassword("mypassword")
  assert.NotNil(t,hash)
  assert.EqualValues(t, err, nil)
}

func TestComparePassword(t *testing.T){
  isFalse := CheckPasswordHash("mypass", "qoieuoqwiueoiqweq2384029")
  assert.EqualValues(t, false, isFalse)
}
