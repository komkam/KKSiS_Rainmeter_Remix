[Variables]

;---- Style ----
@Include5=#@#Include\PanelStyleSmall.inc


;---- Measures Volume ----

[VolumeWin]
Measure				=Plugin
Plugin				=Win7AudioPlugin
UpdateDivider		=1

[VolumeWinPercent]
Measure				=Calc
Formula				=VolumeWin
UpdateDivider		=3
IfCondition			=(VolumeWinPercent < 1)
IfTrueAction		=[!SetVariable CurVol "0"]
IfCondition2		=(VolumeWinPercent > 0) && (VolumeWinPercent < 30)
IfTrueAction2		=[!SetVariable CurVol "30"]
IfCondition3		=(VolumeWinPercent > 29) && (VolumeWinPercent < 60)
IfTrueAction3		=[!SetVariable CurVol "60"]
IfCondition4		=(VolumeWinPercent > 59)
IfTrueAction4		=[!SetVariable CurVol "90"]
DynamicVariables	=1


;---- Standard Meters ----

[VolumeIconA]
	Meter=Image
	ImageName=#@#Images\Icons\Volume#CurVol##VolumeColoredIcons#.png
	X=(#PHeight#*0.06)
	Y=(#PHeight#*0.04)
	W=(#PHeight#*0.3)
	H=(#PHeight#*0.3)
	DynamicVariables=1
	UpdateDivider=3	
[VolumeIconB]
	Meter=Image
	ImageName=#@#Images\Icons\Volume#CurVol##VolumeColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.3)
	H=(#PHeight#*0.3)
	Hidden=#VolumeColoredIcons#
	DynamicVariables=1
	UpdateDivider=3

[VolumeText]
	Meter=String
	MeterStyle=PText | PInfo
	X=(#PHeight#*0.38)
	Y=(#PHeight#*0.18)
	MeasureName=VolumeWinPercent
	Text=Vol: %1
	UpdateDivider=3
	Hidden=#VolumeHideVol#
	

[TitleOutput]
Meter=String
MeterStyle=PText | PInfo
MeasureName=VolumeWin
X=(#PHeight#*0.38)
Y=(#PHeight#*(0.06*#VolumeHideVol#+0.05))
Text=%1
Hidden=#VolumeHideOutput#
DynamicVariables=1
Updatedivider=1

[Title]
Meter=String
MeterStyle=PText | PInfo
X=(#PHeight#*0.38)
Y=(#PHeight#*(0.06*#VolumeHideVol#+0.05))
Text=#VarVolume#
Hidden=(1-#VolumeHideOutput#)
DynamicVariables=1
Updatedivider=-1


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
LeftMouseUpAction=[!CommandMeasure "VolumeWin" "ToggleMute"]
MouseScrollDownAction=[!CommandMeasure "VolumeWin" "ChangeVolume -2"]
MouseScrollUpAction=[!CommandMeasure "VolumeWin" "ChangeVolume +2"]

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size