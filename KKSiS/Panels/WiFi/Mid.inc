[Variables]

;---- Style ----
@Include5=#@#Include\PanelStyleMid.inc


;---- Measures WiFi ----

[Measure_WiFiQuality]
Measure				=Plugin
Plugin				=WiFiStatus
WiFiInfoType		=Quality
UpdateDivider		=1
IfCondition			=(Measure_WiFiQuality = 0)
IfTrueAction		=[!SetVariable CurQual "0"]
IfCondition2		=(Measure_WiFiQuality > 0) && (Measure_WiFiQuality < 25)
IfTrueAction2		=[!SetVariable CurQual "25"]
IfCondition3		=(Measure_WiFiQuality > 24) && (Measure_WiFiQuality < 50)
IfTrueAction3		=[!SetVariable CurQual "50"]
IfCondition4		=(Measure_WiFiQuality > 49) && (Measure_WiFiQuality < 75)
IfTrueAction4		=[!SetVariable CurQual "75"]
IfCondition5		=(Measure_WiFiQuality > 74)
IfTrueAction5		=[!SetVariable CurQual "100"]

[Measure_WiFiSSID]
Measure				=Plugin
Plugin				=WiFiStatus
WiFiInfoType		=SSID
UpdateDivider		=5

[Measure_WiFiEncryption]
Measure				=Plugin
Plugin				=WiFiStatus
WiFiInfoType		=Encryption
UpdateDivider		=5

[Measure_WiFiAUTH]
Measure				=Plugin
Plugin				=WiFiStatus
WiFiInfoType		=AUTH
UpdateDivider		=5

[Measure_WiFiPHY]
Measure				=Plugin
Plugin				=WiFiStatus
WiFiInfoType		=PHY
UpdateDivider		=5

[Measure_Bandwidth]
Measure				=Plugin
Plugin				=UsageMonitor
Category			=Network Adapter
Counter				=Current Bandwidth
Index				=#WiFiAdapterIndex#
UpdateDivider		=5

[Measure_WiFiBandwidth]
Measure				=Calc
Formula				=[Measure_Bandwidth:]*1.024*1.024
DynamicVariables	=1
UpdateDivider		=5


;---- Standard Meters ----

[WiFiIconA]
	Meter=Image
	ImageName=#@#Images\Icons\WiFi#CurQual##WiFiColoredIcons#.png
	X=(#PHeight#*0.15)
	Y=(#PHeight#*0.1)
	W=(#PHeight#*0.8)
	H=(#PHeight#*0.8)
	DynamicVariables=1
	UpdateDivider=3	
[WiFiIconB]
	Meter=Image
	ImageName=#@#Images\Icons\WiFi#CurQual##WiFiColoredIcons#.png
	ImageTint=#Panel-ButtonColor#
	X=0r
	Y=0r
	W=(#PHeight#*0.8)
	H=(#PHeight#*0.8)
	Hidden=#WiFiColoredIcons#
	DynamicVariables=1
	UpdateDivider=3

[WiFiText]
	Meter=String
	MeterStyle=PText | PSize3
	X=(#PHeight#*0.08)
	Y=(#PHeight#*0.05)
	MeasureName=Measure_WiFiQuality
	Text=%1%
	UpdateDivider=1
	Hidden=#WiFiHideQuality#

[TitleOutput]
Meter=String
MeterStyle=PText | PTitle
MeasureName=Measure_WiFiSSID
Text=%1
Hidden=#WiFiHideSSID#
DynamicVariables=1
Updatedivider=1

[Title]
Meter=String
MeterStyle=PText | PTitle
Text=WiFi
Hidden=(1-#WiFiHideSSID#)
DynamicVariables=1
Updatedivider=-1


;---- WiFi Details ----

[WiFiDetailsBackground]
	Meter=Shape
	Shape=Rectangle (#PHeight#*0.040),(#PHeight#*0.040),(#PHeight#),(#PHeight#),(#PHeight#*0.032) | Fill Color 0,0,0,210 | StrokeWidth 0
	DynamicVariables=1
	AntiAlias=1
	Updatedivider=-1
	Group=WiFiDetails
	Hidden=1

[WiFiDetailsTitle]
	Meter=String
	MeterStyle=PText | PTitle
	Text=Details
	UpdateDivider=20
	Group=WiFiDetails
	Hidden=1
	
[WiFiDetails_Encryption]
	Meter=String
	MeasureName=Measure_WiFiEncryption
	MeterStyle=PText | PInfo | PCenterMid
	FontColor=210,210,210
	Y=(#PHeight#*0.1)
	Text=%1
	Group=WiFiDetails
	Hidden=1
	
[WiFiDetails_AUTH]
	Meter=String
	MeasureName=Measure_WiFiAUTH
	MeterStyle=PText | PInfo | PCenterMid
	FontColor=210,210,210
	Y=(#PHeight#*0.3)
	Text=%1
	Group=WiFiDetails
	Hidden=1
	
[WiFiDetails_PHY]
	Meter=String
	MeasureName=Measure_WiFiPHY
	MeterStyle=PText | PInfo | PCenterMid
	FontColor=210,210,210
	Y=(#PHeight#*0.5)
	Text=%1
	Group=WiFiDetails
	Hidden=1
	
[WiFiDetails_Bandwidth]
	Meter=String
	MeasureName=Measure_WiFiBandwidth
	MeterStyle=PText | PInfo | PCenterMid
	FontColor=210,210,210
	Y=(#PHeight#*0.7)
	Text=%1bits/s
	AutoScale=1
	NumOfDecimals=0
	Group=WiFiDetails
	Hidden=1
	

;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
MouseOverAction=[!ShowMeterGroup WiFiDetails][!HideMeterGroup WiFiTitle]
MouseLeaveAction=[!HideMeterGroup WiFiDetails][!Refresh]

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size