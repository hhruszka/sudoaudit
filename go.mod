module sudoaudit

go 1.21

replace github.com/zRedShift/mimemagic/v2 => ./mimemagic-2.0.0

//require github.com/zRedShift/mimemagic/v2 v2.0.0-00010101000000

require github.com/zRedShift/mimemagic/v2 v2.0.0-00010101000000-000000000000

require (
	golang.org/x/crypto v0.12.0 // indirect
	golang.org/x/net v0.10.0 // indirect
	golang.org/x/sys v0.11.0 // indirect
	golang.org/x/term v0.11.0 // indirect
	golang.org/x/text v0.12.0 // indirect
)
