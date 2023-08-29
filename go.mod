module sudoaudit

go 1.21

replace github.com/zRedShift/mimemagic/v2 => ./mimemagic-2.0.0

//require github.com/zRedShift/mimemagic/v2 v2.0.0-00010101000000

require github.com/zRedShift/mimemagic/v2 v2.0.0-00010101000000-000000000000

require (
	golang.org/x/net v0.0.0-20181017193950-04a2e542c03f // indirect
	golang.org/x/text v0.3.0 // indirect
)
