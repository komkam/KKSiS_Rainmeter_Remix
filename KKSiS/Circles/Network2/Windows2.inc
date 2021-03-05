;---- Windows Measures ----

[Measure_LANIN]
Measure			=NetIn
Interface		=#LAN2Interface#
UseBits			=1
NetInSpeed		=(#LAN2MaxInValueInMBits#*1024*1024)
UpdateDivider	=1
DynamicVariables=1

[Measure_MaxIn]
Measure			=Calc
Formula			=#LAN2MaxInValueInMBits#*1024*1024
UpdateDivider	=20
DynamicVariables=1

[Measure_MaxIn_inBytes]
Measure			=Calc
Formula			=Measure_MaxIn/8
UpdateDivider	=20
DynamicVariables=1

[Measure_LANOUT]
Measure			=NetOut
Interface		=#LAN2Interface#
UseBits			=1
NetInSpeed		=(#LAN2MaxOutValueInMBits#*1024*1024)
UpdateDivider	=1
DynamicVariables=1

[Measure_MaxOut]
Measure			=Calc
Formula			=#LAN2MaxOutValueInMBits#*1024*1024
UpdateDivider	=20
DynamicVariables=1

[Measure_MaxOut_inBytes]
Measure			=Calc
Formula			=Measure_MaxOut/8
UpdateDivider	=20
DynamicVariables=1

[Measure_LANName]
Measure			=Plugin
Plugin			=SysInfo
SysInfoType		=ADAPTER_DESCRIPTION
SysInfoData		=#LAN2Interface#
Substitute		=#Network2FilterWindows#
UpdateDivider	=10
DynamicVariables=1
UpdateDivider	=-1

[Measure_LANIP]
Measure			=Plugin
Plugin			=SysInfo
SysInfoType		=IP_ADDRESS
SysInfoData		=#LAN2Interface#
UpdateDivider	=10
DynamicVariables=1
UpdateDivider	=50

[Measure_InternetConnectivity]
Measure			=Plugin
Plugin			=SysInfo
SysInfoType		=INTERNET_CONNECTIVITY
SysInfoData		=#LAN2Interface#
DynamicVariables=1
UpdateDivider	=50
IfCondition		=(#NetworkHideGraph2# = 0)
IfTrueAction	=[!HideMeter Info3IconA][!HideMeter Info3IconB][!HideMeter Info3Text][!HideMeter Info4IconA][!HideMeter Info4IconB][!HideMeter Info4Text]


;---- Roundline Calculations ----

[SmoothLeftRoundline]
Measure			=Calc
Formula			=100-100*((Measure_LANIN*8+0.1)/(Measure_MaxIn+0.1))
UpdateDivider	=1
AverageSize		=40

[SmoothRightRoundline]
Measure			=Calc
Formula			=100-100*((Measure_LANOUT*8+0.1)/(Measure_MaxOut+0.1))
UpdateDivider	=1
AverageSize		=40


;---- Roundline 0 - 100 ----

[Measure-Roundline-Left]
Meter=Roundline
MeterStyle=Roundline-Left
MeasureName=SmoothLeftRoundline
ValueRemainder=100
Updatedivider=1

[Measure-Roundline-Right]
Meter=Roundline
MeterStyle=Roundline-Right
MeasureName=SmoothRightRoundline
ValueRemainder=100
Updatedivider=1

[LD-20]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-199.3))
[LD-40]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-172.3))
[LD-60]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-145.3))
[LD-80]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-118.3))
UpdateDivider=100
[LD+80]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-62.7))
UpdateDivider=100
[LD+60]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-35.7))
[LD+40]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(-8.7))
[LD+20]
Meter=Roundline
MeterStyle=LineDivider
StartAngle=(Rad(18.3))

[GlossyEffect]
Meter=Shape
MeterStyle=GlossyEffectStyle


;---- Roundline Left Meter ----

[SensorUnit]
	Meter=String
	MeterStyle=CText | CSize6 | CCenter
	Y=(#CRadius#*0.080)
	Text=b/s
	Hidden=#Network2HideRLLabel#
	UpdateDivider=-1
	
[SensorLeftMax]
	Meter=String
	MeterStyle=CText | CSize6
	MeasureName=Measure_MaxIn
	StringAlign=Right
	X=(#CRadius#*0.980)
	Y=(#CRadius#*0.160)
	Text=%1
	Autoscale=1
	NumOfDecimals=1
	Hidden=#Network2HideRLLabel#
	UpdateDivider=50
	
[SensorLeftMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Right
	Angle=(Rad(-45))
	X=(#CRadius#*0.396)
	Y=(#CRadius#*1.454)
	Text=0
	Autoscale=1
	Hidden=#Network2HideRLLabel#
	UpdateDivider=-1


;---- Roundline Right Meter ----

[SensorRightMax]
	Meter=String
	MeterStyle=CText | CSize6
	MeasureName=Measure_MaxOut
	StringAlign=Left
	X=(#CRadius#*1.020)
	Y=(#CRadius#*0.160)
	Text=%1
	Autoscale=1
	NumOfDecimals=1
	Hidden=#Network2HideRLLabel#
	UpdateDivider=50
	
[SensorRightMin]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Left
	Angle=(Rad(45))
	X=(#CRadius#*1.604)
	Y=(#CRadius#*1.454)
	Text=0
	Hidden=#Network2HideRLLabel#
	UpdateDivider=-1
	

;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
LeftMouseUpAction=[Shell:::{7007ACC7-3202-11D1-AAD2-00805FC1270E}]
Updatedivider=-1


;---- Graph ----

[GraphLabel1]
	Meter=String
	MeterStyle=CText | CSize9
	StringAlign=Left
	FontColor=#Circle-RoundlineFillColor1#
	X=(#CRadius#*0.31)
	Y=(#CRadius#*0.79)
	Text=IN
	Hidden=#NetworkHideGraph2#

[GraphLabel2]
	Meter=String
	MeterStyle=CText | CSize9
	StringAlign=Right
	FontColor=#Circle-RoundlineFillColor3#
	X=(#CRadius#*1.69)
	Y=(#CRadius#*0.79)
	Text=OUT
	Hidden=#NetworkHideGraph2#

[Graph]
	Meter=Line
	MeasureName=Measure_LANIN
	MeasureName2=Measure_LANOUT
	LineCount=2
	MeterStyle=HWiNFOGraphStyle2
	Hidden=#NetworkHideGraph2#

	
;---- Standard Meter ----	

[Info1IconA]
	Meter=Image
	ImageName=#@#Images\Icons\NetIn#Network2ColoredIcons#.png
	X=(#CRadius#*0.6)
	Y=(#CRadius#*(0.52-0.07*#NetworkHideGraph2#))
	W=(#CRadius#*0.25)
	H=(#CRadius#*0.25)
	DynamicVariables=1
	UpdateDivider=-1	
[Info1IconB]
	Meter=Image
	ImageName=#@#Images\Icons\NetIn#Network2ColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.25)
	H=(#CRadius#*0.25)
	Hidden=#Network2ColoredIcons#
	DynamicVariables=1
	UpdateDivider=-1
[Info1TextA]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.3)r
	MeasureName=Measure_LANIN
	Text=%1B/s
	Autoscale=1
	NumOfDecimals=1
	UpdateDivider=10
[Info1TextB]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Left
	X=0r
	Y=(#CRadius#*0.15)r
	MeasureName=Measure_MaxIn_inBytes
	Text=%1B/s
	Autoscale=1
	NumOfDecimals=1
	DynamicVariables=1
	UpdateDivider=50

[Info2IconA]
	Meter=Image
	ImageName=#@#Images\Icons\NetOut#Network2ColoredIcons#.png
	X=(#CRadius#*0.6)
	Y=(#CRadius#*1.2)
	W=(#CRadius#*0.25)
	H=(#CRadius#*0.25)
	DynamicVariables=1
	UpdateDivider=-1
[Info2IconB]
	Meter=Image
	ImageName=#@#Images\Icons\NetOut#Network2ColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.25)
	H=(#CRadius#*0.25)
	Hidden=#Network2ColoredIcons#
	DynamicVariables=1
	UpdateDivider=-1
[Info2TextA]
	Meter=String
	MeterStyle=CText | CInfo
	X=(#CRadius#*0.3)r
	MeasureName=Measure_LANOUT
	Text=%1B/s
	Autoscale=1
	NumOfDecimals=1
	UpdateDivider=10
[Info2TextB]
	Meter=String
	MeterStyle=CText | CSize6
	StringAlign=Left
	X=0r
	Y=(#CRadius#*0.15)r
	MeasureName=Measure_MaxOut_inBytes
	Text=%1B/s
	Autoscale=1
	NumOfDecimals=1
	DynamicVariables=1
	UpdateDivider=50

[Info3IconA]
	Meter=Image
	ImageName=#@#Images\Icons\Chip#Network2ColoredIcons#.png
	X=(-#CRadius#*0.25)r
	Y=(#CRadius#*0.78)
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info3IconB]
	Meter=Image
	ImageName=#@#Images\Icons\Chip#Network2ColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#Network2ColoredIcons#
	DynamicVariables=1
[Info3Text]
	Meter=String
	MeterStyle=CText | CInfo | CSize5
	Y=(#CRadius#*0.005)r
	MeasureName=Measure_LANIP
	Text=%1
	DynamicVariables=1

[Info4IconA]
	Meter=Image
	ImageName=#@#Images\Icons\[Measure_InternetConnectivity]#Network2ColoredIcons#.png
	X=(-#CRadius#*0.2)r
	Y=(#CRadius#*(0.19+0.03*#Network2HideGraph1#))r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	DynamicVariables=1
[Info4IconB]
	Meter=Image
	ImageName=#@#Images\Icons\[Measure_InternetConnectivity]#Network2ColoredIcons#.png
	ImageTint=#Circle-ButtonColor#
	X=0r
	Y=0r
	W=(#CRadius#*0.16)
	H=(#CRadius#*0.16)
	Hidden=#Network2ColoredIcons#
	DynamicVariables=1
[Info4Text]
	Meter=String
	MeterStyle=CText | CInfo | CSize5
	Y=(#CRadius#*0.005)r
	Text=Internet

[Title]
Meter=String
MeterStyle=CText | CTitle
MeasureName=Measure_LANName
Text=#LAN2NameWin#	
DynamicVariables=1
Updatedivider=-1


;---- Skin Functions ----

[ChangeCircleSize]
Meter=Shape
MeterStyle=Change-Circle-Size
UpdateDivider=-1

