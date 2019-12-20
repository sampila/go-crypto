package gocrypto

import(
  "testing"
  "os"
  "github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M){
  os.Exit(m.Run())
}

func TestHashPasswordOK(t *testing.T){
  hash, err := HashPassword("mypassword")
  assert.NotNil(t,hash)
  assert.EqualValues(t, err, nil)
}

func TestComparePasswordInvalid(t *testing.T){
  isFalse := CheckPasswordHash("mypass", "qoieuoqwiueoiqweq2384029")
  assert.EqualValues(t, false, isFalse)
}
