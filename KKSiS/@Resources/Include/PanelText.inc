;---- Text Style for Circles ----

[PStations]
	FontFace=Calibri
	FontSize=(#PHeight#*0.10)
	InlineSetting=Shadow | 0 | 0 | 2 | 255,255,255
	StringStyle=Normal
	StringAlign=Left
	FontColor=210,210,210,255
	X=(#PHeight#*0.05)
	Y=(#PHeight#*0.12)r	
	W=(#PHeight#*0.95)
	Clipstring=1
	Hidden=1
	Group=Stations
	AntiAlias=1
	DynamicVariables=1

[PStationsBigPanel]
	FontFace=Calibri
	FontSize=(#PHeight#*0.09)
	InlineSetting=Shadow | 0 | 0 | 2 | #Panel-ButtonColor#
	StringStyle=Normal
	StringAlign=Left
	FontColor=#Panel-FontColor#
	X=(#PHeight#*1.1)
	W=(#PHeight#*0.85)
	Clipstring=1
	AntiAlias=1
	DynamicVariables=1
	UpdateDivider=1

[PText]
	FontFace=Calibri
	FontColor=#Panel-FontColor#
	StringStyle=Normal
	AntiAlias=1
	DynamicVariables=1

[PTitle]
	FontSize=(#PHeight#*0.07)
	StringAlign=Center
	X=(#PHeight#*0.538)
	Y=(#PHeight#*0.93)
	Clipstring=1
	W=(#PHeight#)
	
[PTitle2]
	FontSize=(#PHeight#*0.07)
	StringAlign=Center
	X=(#PHeight#*1.038)
	Y=(#PHeight#*0.93)
	
[PTitle90]
	FontSize=(#PHeight#*0.07)
	StringAlign=Center
	Angle=(Rad(90))
	X=(#PHeight#*0.15)
	Y=(#PHeight#*0.5)
	Clipstring=1
	W=(#PHeight#)
	
[PSize0]
	FontSize=(#PHeight#*0.16)

[PSize1]
	FontSize=(#PHeight#*0.14)

[PSize2]
	FontSize=(#PHeight#*0.12)

[PSize3]
	FontSize=(#PHeight#*0.10)

[PSize4]
	FontSize=(#PHeight#*0.09)

[PSize5]
	FontSize=(#PHeight#*0.08)

[PSize6]
	FontSize=(#PHeight#*0.07)

[PSize7]
	FontSize=(#PHeight#*0.06)

[PSize8]
	FontSize=(#PHeight#*0.05)

[PSize9]
	FontSize=(#PHeight#*0.04)

[PSize10]
	FontSize=(#PHeight#*0.03)
	
[PCenterMid]
	StringAlign=Center
	X=(#PHeight#*0.538)

[PCenterBig]
	StringAlign=Center
	X=(#PHeight#*1.038)

[PInfo]
	FontSize=(#PHeight#*0.09)
	StringAlign=Left
	X=(#PHeight#*0.2)r
	Y=(-#PHeight#*0.015)r
	X=#PHeight#



