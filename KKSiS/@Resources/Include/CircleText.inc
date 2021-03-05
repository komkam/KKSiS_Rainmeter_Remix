;---- Text Style for Circles ----

[CStations]
	FontFace=Calibri
	InlineSetting=Shadow | 0 | 0 | 3.5 | #Circle-RoundlineFillColor1#
	FontSize=(#CRadius#*0.17)
	StringStyle=Normal
	StringAlign=Left
	FontColor=210,210,210,255
	X=(#CRadius#*0.1)
	W=(#CRadius#*1.85)
	Clipstring=1
	Hidden=1
	Group=Stations
	AntiAlias=1
	DynamicVariables=1

[CText]
	FontFace=Calibri
	FontColor=#Circle-FontColor#
	StringStyle=Normal
	AntiAlias=1
	DynamicVariables=1

[CTitle]
	FontSize=(#CRadius#*0.12)
	StringAlign=Center
	X=#CRadius#
	Y=(#CRadius#*1.58)
	W=(#CRadius#*1.2)
	Clipstring=1

[CSize0]
	FontSize=(#CRadius#*0.26)

[CSize1]
	FontSize=(#CRadius#*0.21)

[CSize2]
	FontSize=(#CRadius#*0.18)

[CSize3]
	FontSize=(#CRadius#*0.15)

[CSize4]
	FontSize=(#CRadius#*0.12)

[CSize5]
	FontSize=(#CRadius#*0.09)

[CSize6]
	FontSize=(#CRadius#*0.07)

[CSize7]
	FontSize=(#CRadius#*0.06)

[CSize8]
	FontSize=(#CRadius#*0.05)

[CSize9]
	FontSize=(#CRadius#*0.04)

[CSize10]
	FontSize=(#CRadius#*0.03)
	
[CCenter]
	StringAlign=Center
	X=#CRadius#

[CInfo]
	FontSize=(#CRadius#*0.11)
	StringAlign=Left
	X=(#CRadius#*0.2)r
	Y=(-#CRadius#*0.02)r
	X=#CRadius#


