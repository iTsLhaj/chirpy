package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

var jwtSecret = "*$*^.!1A(2B)C3.%*%.D4(E5)6F!.^*$*"

var passwords []string = []string{
	"123456",
	"password",
	"12345678",
	"qwerty",
	"123456789",
	"12345",
	"1234",
	"111111",
	"1234567",
	"dragon",
	"123123",
	"baseball",
	"abc123",
	"football",
	"monkey",
	"letmein",
	"shadow",
	"master",
	"666666",
	"qwertyuiop",
	"123321",
	"mustang",
	"1234567890",
	"michael",
	"654321",
	"superman",
	"1qaz2wsx",
	"7777777",
	"121212",
	"000000",
	"qazwsx",
	"123qwe",
	"killer",
	"trustno1",
	"jordan",
	"jennifer",
	"zxcvbnm",
	"asdfgh",
	"hunter",
	"buster",
	"soccer",
	"harley",
	"batman",
	"andrew",
	"tigger",
	"sunshine",
	"iloveyou",
	"2000",
	"charlie",
	"robert",
	"thomas",
	"hockey",
	"ranger",
	"daniel",
	"starwars",
	"klaster",
	"112233",
	"george",
	"computer",
	"michelle",
	"jessica",
	"pepper",
	"1111",
	"zxcvbn",
	"555555",
	"11111111",
	"131313",
	"freedom",
	"777777",
	"pass",
	"maggie",
	"159753",
	"aaaaaa",
	"ginger",
	"princess",
	"joshua",
	"cheese",
	"amanda",
	"summer",
	"love",
	"ashley",
	"nicole",
	"chelsea",
	"biteme",
	"matthew",
	"access",
	"yankees",
	"987654321",
	"dallas",
	"austin",
	"thunder",
	"taylor",
	"matrix",
	"mobilemail",
	"mom",
	"monitor",
	"monitoring",
	"montana",
	"moon",
	"moscow",
}

func TestHashPassword(t *testing.T) {
	for _, password := range passwords {
		_, err := HashPassword(password)
		if err != nil {
			t.Error(err)
		}
	}
}

func TestCheckPasswordHash(t *testing.T) {
	var hash string
	var err error
	var ok bool
	for _, password := range passwords {
		hash, err = HashPassword(password)
		if err != nil {
			t.Error(err)
		}
		ok, err = CheckPasswordHash(password, hash)
		if err != nil {
			t.Error(err)
		}
		if !ok {
			t.Errorf(`
the password used for checking is the same as the hashed password.
although <CheckPasswordHash> returned **false** ??
 [*] password: %s
 [*] hash:     %s
`, password, hash)
		}
	}
}

func TestJWT(t *testing.T) {
	rndUUID, err := uuid.NewRandom()
	if err != nil {
		t.Error(err)
	}

	var token string
	token, err = MakeJWT(rndUUID, jwtSecret, time.Minute*5)
	if err != nil {
		t.Error(err)
	}

	var uid uuid.UUID
	uid, err = ValidateJWT(token, jwtSecret)
	if err != nil {
		t.Error(err)
	}

	if uid.String() != rndUUID.String() {
		t.Errorf("got %q expected %q", uid.String(), rndUUID.String())
	}
}

func TestGetBearerToken(t *testing.T) {
	var mockToken string = "my-jwt-token"
	var mockReq *http.Request

	t.Run("basic check", func(t *testing.T) {
		mockReq = httptest.NewRequest("GET", "/", nil)
		mockReq.Header.Add("Authorization", fmt.Sprintf("Bearer %s", mockToken))

		token, err := GetBearerToken(mockReq.Header)
		if err != nil {
			t.Error(err)
		}
		if token != mockToken {
			t.Errorf("got %q expected %q", token, mockToken)
		}
	})

	t.Run("no authorization header", func(t *testing.T) {
		mockReq = httptest.NewRequest("GET", "/", nil)

		_, err := GetBearerToken(mockReq.Header)
		assertError(t, err)
	})

	t.Run("invalid authorization header", func(t *testing.T) {
		mockReq = httptest.NewRequest("GET", "/", nil)
		mockReq.Header.Add("Authorization", "invalid")

		_, err := GetBearerToken(mockReq.Header)
		assertError(t, err)
	})
}

func assertError(t testing.TB, err error) {
	t.Helper()

	if err == nil {
		t.Error("expected error, got none")
	}
}
