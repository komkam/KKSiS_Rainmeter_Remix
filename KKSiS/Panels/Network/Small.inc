[Variables]

;---- Style ----
@Include6=#@#Include\PanelStyleSmall.inc


[Measure_LANIN]
Measure			=NetIn
Interface		=#LANInterface#
UseBits			=1
NetInSpeed		=(#LANMaxInValueInMBits#*1024*1024)
UpdateDivider	=1
DynamicVariables=1

[Measure_LANOUT]
Measure			=NetOut
Interface		=#LANInterface#
UseBits			=1
NetInSpeed		=(#LANMaxOutValueInMBits#*1024*1024)
UpdateDivider	=1
DynamicVariables=1


;---- Standard Meters ----

[NetworkIconA]
	Meter=Image
	ImageName=#@#Images\Icons\Network#NetworkColoredIcons#.png
	X=(#PHeight#*0.06)
	Y=(#PHeight#*0.08)
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	DynamicVariables=1
	UpdateDivider=3	
[NetworkIconB]
	Meter=Image
	ImageName=#@#Images\Icons\Network#NetworkColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.22)
	H=(#PHeight#*0.22)
	Hidden=#NetworkColoredIcons#
	DynamicVariables=1
	UpdateDivider=3

[NetworkTextA]
	Meter=String
	MeterStyle=PText | PInfo
	X=(#PHeight#*0.31)
	Y=(#PHeight#*0.05)
	MeasureName=Measure_LANIN
	Text=%1B/s
	Autoscale=1
	NumOfDecimals=1
	UpdateDivider=10

[NetworkTextB]
	Meter=String
	MeterStyle=PText | PInfo
	MeasureName=Measure_LANOUT
	X=(#PHeight#*0.31)
	Y=(#PHeight#*0.17)
	Text=%1B/s
	Autoscale=1
	NumOfDecimals=1
	UpdateDivider=10


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
LeftMouseUpAction=[Shell:::{7007ACC7-3202-11D1-AAD2-00805FC1270E}]

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size