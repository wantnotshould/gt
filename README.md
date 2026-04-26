# gt (Go TOTP)

**gt** is a minimalist, secure TOTP (Time-based One-Time Password) library for Go.

## Quick Start

### Install

```bash
go get -u github.com/wantnotshould/gt
```
### Usage

Instead of just calling a functionf, **gt** encourages you to provide a `Store` interface.

**Why?** Because TOTP codes are valid for a 30-second window. To prevent **Replay Attacks**, you need to keep track of the last used timestamp. This library makes that "mandatory-ish" for production safety.

```go
// Implement this with Redis, Memcached, or your DB
type Store interface {
    GetLastTimestamp(key string) (int64, error)
    SetLastTimestamp(key string, timestamp int64) error
}

// Initialize
totp := gt.New(gt.Config{
    Window: 1, // Allow 1-step clock drift (±30s)
}, myStore)

// Validate 
// If valid, the Store automatically updates to prevent reuse.
ok, err := totp.Validate("user_123", "SECRET_KEY", "123456")
```

## CLI Usage

### Install

```bash
go install github.com/wantnotshould/gt/cmd/gt@latest
```

### Configuration

By default, the CLI lookd for a JSON config file at `~/.gi.json`. Create it with your account details.

```json
[
  {
    "label": "github",
    "secret": "JBSWY3DPEHPK3PXP",
    "algorithm": "SHA1",
    "period": 30,
    "digits": 6
  },
  {
    "label": "google",
    "secret": "KRSXG5CTMVRXEZLU",
    "algorithm": "SHA1",
    "period": 30,
    "digits": 6
  }
]
```

### Run it

There are two ways to get your codes.

#### Use a saved account

Run the command with the label you defined in your JSON.

```bash
gt github
```

*If you just run `gt`, it will list all available labels from your config.*

#### Quick check

Pass a secret directly without saving it to a file:

```bash
gt -s JBSWY3DPEHPK3PXP
```

### Interactive UI

Once started, the CLI will stay open and auto-refresh the code every second, showing you exactly how much time is left before the code expires:

```text
Account: github
Press Ctrl+C to stop.
--------------------------
Code: 123456  Expires in: 12s
```

### Pro Tip for CLI users

If you want to keep your config file elsewhere, use the `-c` flag:

```bash
gt -c /path/to/your/config.json my-account
```

## ⚖️ License

MIT License. See [LICENSE](./LICENSE).