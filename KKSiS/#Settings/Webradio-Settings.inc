;---- Skin Toggle ----

[Background1]
Meter=Shape
Shape=Rectangle 10,35,100,95,3 | Fill Color 50,50,50

[Title1]
Meter=String
MeterStyle=SettingsStyle-Text
X=15
Y=40
Text=#VarToggle#

[Divider1]
Meter=Shape
Shape=Rectangle 12,55,96,2,0 | Fill Color 160,160,160

[Toggle1a]
Meter=Button
ButtonImage=#@#Images\Buttons\BtnToggle.png
X=20
Y=65
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Panels\Webradio" "Webradio.ini"]

[Toggle1aText]
Meter=String
MeterStyle=SettingsStyle-Text
X=30r
Y=5r
Text=Panel Skin

[Toggle1b]
Meter=Button
ButtonImage=#@#Images\Buttons\BtnToggle.png
X=-30r
Y=23r
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Circles\Webradio" "Webradio.ini"]

[Toggle1bText]
Meter=String
MeterStyle=SettingsStyle-Text
X=30r
Y=5r
Text=Circle Skin


;---- Panel Skin Size ----

[Background2]
Meter=Shape
Shape=Rectangle 120,35,100,95,3 | Fill Color 50,50,50

[Title2]
Meter=String
MeterStyle=SettingsStyle-Text
X=125
Y=40
Text=#VarPanelSize#

[Divider2]
Meter=Shape
Shape=Rectangle 122,55,96,2,0 | Fill Color 160,160,160

[Button2a]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn80x14.png
X=130
Y=65
ButtonCommand=[!WriteKeyValue Variables "Panel-WRSize" "Small" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"]
[Button2aText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=40r
Y=0r
Text=#VarSmall#

[Button2b]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn80x14.png
X=130
Y=21r
ButtonCommand=[!WriteKeyValue Variables "Panel-WRSize" "Mid" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"]
[Button2bText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=40r
Y=0r
Text=#VarSquare#

[Button2c]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn80x14.png
X=130
Y=21r
ButtonCommand=[!WriteKeyValue Variables "Panel-WRSize" "Big" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"]
[Button2cText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=40r
Y=0r
Text=#VarBig#


;---- Options ----

[Background3]
Meter=Shape
Shape=Rectangle 230,35,160,95,3 | Fill Color 50,50,50

[Title3]
Meter=String
MeterStyle=SettingsStyle-Text
X=235
Y=40
Text=#VarOptions#

[Divider3]
Meter=Shape
Shape=Rectangle 232,55,156,2,0 | Fill Color 160,160,160

[ButtonDescription31]
Meter=String
MeterStyle=SettingsStyle-Text
Text=AudioBar Style
X=235
Y=65
[Button31a]
Meter=Button
ButtonImage=#@#Images\Buttons\Format1b.png
X=106r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "WRAudioBarFormat" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"][!Refresh]
[Button31b]
Meter=Button
ButtonImage=#@#Images\Buttons\Format2b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "WRAudioBarFormat" "2" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"][!Refresh]
[Button31c]
Meter=Button
ButtonImage=#@#Images\Buttons\Format3b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "WRAudioBarFormat" "3" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"][!Refresh]
[Button31Measure]
Measure=Calc
Formula=#WRAudioBarFormat#
IfCondition=(#WRAudioBarFormat# = 1)
IfTrueAction=[!SetOption Button31a ButtonImage "#@#Images\Buttons\Format1a.png"]
IfCondition2=(#WRAudioBarFormat# = 2)
IfTrueAction2=[!SetOption Button31b ButtonImage "#@#Images\Buttons\Format2a.png"]
IfCondition3=(#WRAudioBarFormat# = 3)
IfTrueAction3=[!SetOption Button31c ButtonImage "#@#Images\Buttons\Format3a.png"]


[ButtonDescription32]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarColoredFrame#
X=235
Y=20r
[Button32a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#WRShowColoredBtnFrame#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "WRShowColoredBtnFrame" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"][!Refresh]
[Button32b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#WRShowColoredBtnFrame#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "WRShowColoredBtnFrame" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"][!Refresh]

[ButtonDescription33]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarShowVolume#
X=235
Y=20r
[Button33a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#WRHideVolume#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "WRHideVolume" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"][!Refresh]
[Button33b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#WRHideVolume#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "WRHideVolume" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"][!Refresh]


;-- Stream Config -------------------------------------------------------------------------------- 

[BG3]
Meter=Shape
Shape=Rectangle 10,140,380,65,3 | Fill Color 50,50,50

[T3Text]
Meter=String
MeterStyle=SettingsStyle-Text
Y=145
Text=Stream Configuration

[T3Divider]
Meter=Shape
Shape=Rectangle 12,160,375,2,0 | Fill Color 160,160,160

[Stream1]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn25x25.png
X=20
Y=170
LeftMouseUpAction=[!HideMeterGroup StreamConfig][!ShowMeterGroup Stream1]
[Stream1Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=12r
Y=6r
Text=1

[Stream2]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn25x25.png
X=35r
Y=-6r
LeftMouseUpAction=[!HideMeterGroup StreamConfig][!ShowMeterGroup Stream2]
[Stream2Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=12r
Y=6r
Text=2

[Stream3]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn25x25.png
X=35r
Y=-6r
LeftMouseUpAction=[!HideMeterGroup StreamConfig][!ShowMeterGroup Stream3]
[Stream3Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=12r
Y=6r
Text=3

[Stream4]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn25x25.png
X=35r
Y=-6r
LeftMouseUpAction=[!HideMeterGroup StreamConfig][!ShowMeterGroup Stream4]
[Stream4Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=12r
Y=6r
Text=4

[Stream5]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn25x25.png
X=35r
Y=-6r
LeftMouseUpAction=[!HideMeterGroup StreamConfig][!ShowMeterGroup Stream5]
[Stream5Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=12r
Y=6r
Text=5

[Stream6]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn25x25.png
X=35r
Y=-6r
LeftMouseUpAction=[!HideMeterGroup StreamConfig][!ShowMeterGroup Stream6]
[Stream6Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=12r
Y=6r
Text=6

[Stream7]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn25x25.png
X=35r
Y=-6r
LeftMouseUpAction=[!HideMeterGroup StreamConfig][!ShowMeterGroup Stream7]
[Stream7Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=12r
Y=6r
Text=7

[Stream8]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn25x25.png
X=35r
Y=-6r
LeftMouseUpAction=[!HideMeterGroup StreamConfig][!ShowMeterGroup Stream8]
[Stream8Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=12r
Y=6r
Text=8

[BG4]
Meter=Shape
Shape=Rectangle 10,215,380,390,3 | Fill Color 50,50,50


;-- Stream 1 -------------------------------------------------------------------------------- 

[Meter-Input11-Background]
Meter=Shape
Shape=Rectangle 20,227,175,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input11 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream1
Hidden=0
[Meter-Input12-Background]
Meter=Shape
Shape=Rectangle 205,227,175,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input12 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream1
Hidden=0
[Meter-Input13-Background]
Meter=Shape
Shape=Rectangle 20,252,360,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input13 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream1
Hidden=0
[Meter-Input14-Background]
Meter=Shape
Shape=Rectangle 20,277,360,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input14 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream1
Hidden=0

[Meter-Input11-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=21
Y=230
W=175
Group=StreamConfig | Stream1
Hidden=0
Text=Title1: #StationTitle1#
LeftMouseUpAction=[!CommandMeasure Measure-Input11 "ExecuteBatch 1-2"]
[Meter-Input12-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=185r
Y=0r
W=175
Group=StreamConfig | Stream1
Hidden=0
Text=Image1: #StationImage1#
LeftMouseUpAction=[!CommandMeasure Measure-Input12 "ExecuteBatch 1-2"]
[Meter-Input13-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=-185r
Y=25r
W=355
Group=StreamConfig | Stream1
Hidden=0
Text=Stream1: #StationURL1#
LeftMouseUpAction=[!CommandMeasure Measure-Input13 "ExecuteBatch 1-2"]
[Meter-Input14-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=0r
Y=25r
W=355
Group=StreamConfig | Stream1
Hidden=0
Text=Tracklist1: #StationTrackListURL1#
LeftMouseUpAction=[!CommandMeasure Measure-Input14 "ExecuteBatch 1-2"]

[Measure-Input11]
Measure=Plugin
Plugin=InputText
FontSize=8
W=139
X=53
Y=230
H=14
Group=StreamConfig | Stream1
Hidden=0
FocusDismiss=0
DefaultValue=#StationTitle1#
Command1=[!SetVariable StationTitle1 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationTitle1" [Measure-Input11] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]
[Measure-Input12]
Measure=Plugin
Plugin=InputText
FontSize=8
W=129
X=248
Y=230
H=14
Group=StreamConfig | Stream1
Hidden=0
FocusDismiss=0
DefaultValue=#StationImage1#
Command1=[!SetVariable StationImage1 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationImage1" [Measure-Input12] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]
[Measure-Input13]
Measure=Plugin
Plugin=InputText
FontSize=8
W=310
X=67
Y=255
H=14
Group=StreamConfig | Stream1
Hidden=0
FocusDismiss=0
DefaultValue=#StationURL1#
Command1=[!SetVariable StationURL1 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationURL1" [Measure-Input13] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]
[Measure-Input14]
Measure=Plugin
Plugin=InputText
FontSize=8
W=305
X=72
Y=280
H=14
Group=StreamConfig | Stream1
Hidden=0
FocusDismiss=0
DefaultValue=#StationTrackListURL1#
Command1=[!SetVariable StationTrackListURL1 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationTrackListURL1" [Measure-Input14] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]

[Stream1_Image]
Meter=Image
ImageName=#@#Images\Stations\#StationImage1#
W=100
X=150
Y=320
Group=StreamConfig | Stream1

;-- Stream 2 -------------------------------------------------------------------------------- 

[Meter-Input21-Background]
Meter=Shape
Shape=Rectangle 20,227,175,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input21 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream2
Hidden=1
[Meter-Input22-Background]
Meter=Shape
Shape=Rectangle 205,227,175,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input22 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream2
Hidden=1
[Meter-Input23-Background]
Meter=Shape
Shape=Rectangle 20,252,360,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input23 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream2
Hidden=1
[Meter-Input24-Background]
Meter=Shape
Shape=Rectangle 20,277,360,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input24 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream2
Hidden=1

[Meter-Input21-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=21
Y=230
W=175
Group=StreamConfig | Stream2
Hidden=1
Text=Title2: #StationTitle2#
LeftMouseUpAction=[!CommandMeasure Measure-Input21 "ExecuteBatch 1-2"]
[Meter-Input22-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=185r
Y=0r
W=175
Group=StreamConfig | Stream2
Hidden=1
Text=Image2: #StationImage2#
LeftMouseUpAction=[!CommandMeasure Measure-Input22 "ExecuteBatch 1-2"]
[Meter-Input23-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=-185r
Y=25r
W=355
Group=StreamConfig | Stream2
Hidden=1
Text=Stream2: #StationURL2#
LeftMouseUpAction=[!CommandMeasure Measure-Input23 "ExecuteBatch 1-2"]
[Meter-Input24-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=0r
Y=25r
W=355
Group=StreamConfig | Stream2
Hidden=1
Text=Tracklist2: #StationTrackListURL2#
LeftMouseUpAction=[!CommandMeasure Measure-Input24 "ExecuteBatch 1-2"]

[Measure-Input21]
Measure=Plugin
Plugin=InputText
FontSize=8
W=139
X=53
Y=230
H=14
W=355
Group=StreamConfig | Stream2
Hidden=1
FocusDismiss=0
DefaultValue=#StationTitle2#
Command1=[!SetVariable StationTitle2 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationTitle2" [Measure-Input21] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]
[Measure-Input22]
Measure=Plugin
Plugin=InputText
FontSize=8
W=129
X=248
Y=230
H=14
Group=StreamConfig | Stream2
Hidden=1
FocusDismiss=0
DefaultValue=#StationImage2#
Command1=[!SetVariable StationImage2 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationImage2" [Measure-Input22] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]
[Measure-Input23]
Measure=Plugin
Plugin=InputText
FontSize=8
W=310
X=67
Y=255
H=14
Group=StreamConfig | Stream2
Hidden=1
FocusDismiss=0
DefaultValue=#StationURL2#
Command1=[!SetVariable StationURL2 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationURL2" [Measure-Input23] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]
[Measure-Input24]
Measure=Plugin
Plugin=InputText
FontSize=8
W=305
X=72
Y=280
H=14
Group=StreamConfig | Stream2
Hidden=1
FocusDismiss=0
DefaultValue=#StationTrackListURL2#
Command1=[!SetVariable StationTrackListURL2 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationTrackListURL2" [Measure-Input24] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]

[Stream2_Image]
Meter=Image
ImageName=#@#Images\Stations\#StationImage2#
W=100
X=150
Y=320
Group=StreamConfig | Stream2
Hidden=1

;-- Stream 3 -------------------------------------------------------------------------------- 

[Meter-Input31-Background]
Meter=Shape
Shape=Rectangle 20,227,175,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input31 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream3
Hidden=1
[Meter-Input32-Background]
Meter=Shape
Shape=Rectangle 205,227,175,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input32 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream3
Hidden=1
[Meter-Input33-Background]
Meter=Shape
Shape=Rectangle 20,252,360,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input33 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream3
Hidden=1
[Meter-Input34-Background]
Meter=Shape
Shape=Rectangle 20,277,360,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input34 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream3
Hidden=1

[Meter-Input31-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=21
Y=230
W=175
Group=StreamConfig | Stream3
Hidden=1
Text=Title3: #StationTitle3#
LeftMouseUpAction=[!CommandMeasure Measure-Input31 "ExecuteBatch 1-2"]
[Meter-Input32-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=185r
Y=0r
W=175
Group=StreamConfig | Stream3
Hidden=1
Text=Image3: #StationImage3#
LeftMouseUpAction=[!CommandMeasure Measure-Input32 "ExecuteBatch 1-2"]
[Meter-Input33-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=-185r
Y=25r
W=355
Group=StreamConfig | Stream3
Hidden=1
Text=Stream3: #StationURL3#
LeftMouseUpAction=[!CommandMeasure Measure-Input33 "ExecuteBatch 1-2"]
[Meter-Input34-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=0r
Y=25r
W=355
Group=StreamConfig | Stream3
Hidden=1
Text=Tracklist3: #StationTrackListURL3#
LeftMouseUpAction=[!CommandMeasure Measure-Input34 "ExecuteBatch 1-2"]

[Measure-Input31]
Measure=Plugin
Plugin=InputText
FontSize=8
W=139
X=53
Y=230
H=14
Group=StreamConfig | Stream3
Hidden=1
FocusDismiss=0
DefaultValue=#StationTitle3#
Command1=[!SetVariable StationTitle3 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationTitle3" [Measure-Input31] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]
[Measure-Input32]
Measure=Plugin
Plugin=InputText
FontSize=8
W=129
X=248
Y=230
H=14
Group=StreamConfig | Stream3
Hidden=1
FocusDismiss=0
DefaultValue=#StationImage3#
Command1=[!SetVariable StationImage3 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationImage3" [Measure-Input32] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]
[Measure-Input33]
Measure=Plugin
Plugin=InputText
FontSize=8
W=310
X=67
Y=255
H=14
Group=StreamConfig | Stream3
Hidden=1
FocusDismiss=0
DefaultValue=#StationURL3#
Command1=[!SetVariable StationURL3 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationURL3" [Measure-Input33] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]
[Measure-Input34]
Measure=Plugin
Plugin=InputText
FontSize=8
W=305
X=72
Y=279
H=14
Group=StreamConfig | Stream3
Hidden=1
FocusDismiss=0
DefaultValue=#StationTrackListURL3#
Command1=[!SetVariable StationTrackListURL3 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationTrackListURL3" [Measure-Input34] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]

[Stream3_Image]
Meter=Image
ImageName=#@#Images\Stations\#StationImage3#
W=100
X=150
Y=320
Group=StreamConfig | Stream3
Hidden=1

;-- Stream 4 -------------------------------------------------------------------------------- 

[Meter-Input41-Background]
Meter=Shape
Shape=Rectangle 20,227,175,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input41 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream4
Hidden=1
[Meter-Input42-Background]
Meter=Shape
Shape=Rectangle 205,227,175,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input42 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream4
Hidden=1
[Meter-Input43-Background]
Meter=Shape
Shape=Rectangle 20,252,360,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input43 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream4
Hidden=1
[Meter-Input44-Background]
Meter=Shape
Shape=Rectangle 20,277,360,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input44 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream4
Hidden=1

[Meter-Input41-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=21
Y=230
W=175
Group=StreamConfig | Stream4
Hidden=1
Text=Title4: #StationTitle4#
LeftMouseUpAction=[!CommandMeasure Measure-Input41 "ExecuteBatch 1-2"]
[Meter-Input42-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=185r
Y=0r
W=175
Group=StreamConfig | Stream4
Hidden=1
Text=Image4: #StationImage4#
LeftMouseUpAction=[!CommandMeasure Measure-Input42 "ExecuteBatch 1-2"]
[Meter-Input43-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=-185r
Y=25r
W=355
Group=StreamConfig | Stream4
Hidden=1
Text=Stream4: #StationURL4#
LeftMouseUpAction=[!CommandMeasure Measure-Input43 "ExecuteBatch 1-2"]
[Meter-Input44-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=0r
Y=25r
W=355
Group=StreamConfig | Stream4
Hidden=1
Text=Tracklist4: #StationTrackListURL4#
LeftMouseUpAction=[!CommandMeasure Measure-Input44 "ExecuteBatch 1-2"]

[Measure-Input41]
Measure=Plugin
Plugin=InputText
FontSize=8
W=139
X=53
Y=230
H=14
Group=StreamConfig | Stream4
Hidden=1
FocusDismiss=0
DefaultValue=#StationTitle4#
Command1=[!SetVariable StationTitle4 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationTitle4" [Measure-Input41] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]
[Measure-Input42]
Measure=Plugin
Plugin=InputText
FontSize=8
W=129
X=248
Y=230
H=14
Group=StreamConfig | Stream4
Hidden=1
FocusDismiss=0
DefaultValue=#StationImage4#
Command1=[!SetVariable StationImage4 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationImage4" [Measure-Input42] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]
[Measure-Input43]
Measure=Plugin
Plugin=InputText
FontSize=8
W=310
X=67
Y=255
H=14
Group=StreamConfig | Stream4
Hidden=1
FocusDismiss=0
DefaultValue=#StationURL4#
Command1=[!SetVariable StationURL4 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationURL4" [Measure-Input43] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]
[Measure-Input44]
Measure=Plugin
Plugin=InputText
FontSize=8
W=305
X=72
Y=279
H=14
Group=StreamConfig | Stream4
Hidden=1
FocusDismiss=0
DefaultValue=#StationTrackListURL4#
Command1=[!SetVariable StationTrackListURL4 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationTrackListURL4" [Measure-Input44] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]

[Stream4_Image]
Meter=Image
ImageName=#@#Images\Stations\#StationImage4#
W=100
X=150
Y=320
Group=StreamConfig | Stream4
Hidden=1

;-- Stream 5 -------------------------------------------------------------------------------- 

[Meter-Input51-Background]
Meter=Shape
Shape=Rectangle 20,227,175,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input51 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream5
Hidden=1
[Meter-Input52-Background]
Meter=Shape
Shape=Rectangle 205,227,175,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input52 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream5
Hidden=1
[Meter-Input53-Background]
Meter=Shape
Shape=Rectangle 20,252,360,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input53 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream5
Hidden=1
[Meter-Input54-Background]
Meter=Shape
Shape=Rectangle 20,277,360,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input54 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream5
Hidden=1

[Meter-Input51-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=21
Y=230
W=175
Group=StreamConfig | Stream5
Hidden=1
Text=Title5: #StationTitle5#
LeftMouseUpAction=[!CommandMeasure Measure-Input51 "ExecuteBatch 1-2"]
[Meter-Input52-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=185r
Y=0r
W=175
Group=StreamConfig | Stream5
Hidden=1
Text=Image5: #StationImage5#
LeftMouseUpAction=[!CommandMeasure Measure-Input52 "ExecuteBatch 1-2"]
[Meter-Input53-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=-185r
Y=25r
W=355
Group=StreamConfig | Stream5
Hidden=1
Text=Stream5: #StationURL5#
LeftMouseUpAction=[!CommandMeasure Measure-Input53 "ExecuteBatch 1-2"]
[Meter-Input54-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=0r
Y=25r
W=355
Group=StreamConfig | Stream5
Hidden=1
Text=Tracklist5: #StationTrackListURL5#
LeftMouseUpAction=[!CommandMeasure Measure-Input54 "ExecuteBatch 1-2"]

[Measure-Input51]
Measure=Plugin
Plugin=InputText
FontSize=8
W=139
X=53
Y=230
H=14
Group=StreamConfig | Stream5
Hidden=1
FocusDismiss=0
DefaultValue=#StationTitle5#
Command1=[!SetVariable StationTitle5 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationTitle5" [Measure-Input51] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]
[Measure-Input52]
Measure=Plugin
Plugin=InputText
FontSize=8
W=129
X=248
Y=230
H=14
Group=StreamConfig | Stream5
Hidden=1
FocusDismiss=0
DefaultValue=#StationImage5#
Command1=[!SetVariable StationImage5 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationImage5" [Measure-Input52] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]
[Measure-Input53]
Measure=Plugin
Plugin=InputText
FontSize=8
W=310
X=67
Y=255
H=14
Group=StreamConfig | Stream5
Hidden=1
FocusDismiss=0
DefaultValue=#StationURL5#
Command1=[!SetVariable StationURL5 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationURL5" [Measure-Input53] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]
[Measure-Input54]
Measure=Plugin
Plugin=InputText
FontSize=8
W=305
X=72
Y=279
H=14
Group=StreamConfig | Stream5
Hidden=1
FocusDismiss=0
DefaultValue=#StationTrackListURL5#
Command1=[!SetVariable StationTrackListURL5 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationTrackListURL5" [Measure-Input54] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]

[Stream5_Image]
Meter=Image
ImageName=#@#Images\Stations\#StationImage5#
W=100
X=150
Y=320
Group=StreamConfig | Stream5
Hidden=1

;-- Stream 6 -------------------------------------------------------------------------------- 

[Meter-Input61-Background]
Meter=Shape
Shape=Rectangle 20,227,175,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input61 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream6
Hidden=1
[Meter-Input62-Background]
Meter=Shape
Shape=Rectangle 205,227,175,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input62 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream6
Hidden=1
[Meter-Input63-Background]
Meter=Shape
Shape=Rectangle 20,252,360,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input63 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream6
Hidden=1
[Meter-Input64-Background]
Meter=Shape
Shape=Rectangle 20,277,360,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input64 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream6
Hidden=1

[Meter-Input61-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=21
Y=230
W=175
Group=StreamConfig | Stream6
Hidden=1
Text=Title6: #StationTitle6#
LeftMouseUpAction=[!CommandMeasure Measure-Input61 "ExecuteBatch 1-2"]
[Meter-Input62-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=185r
Y=0r
W=175
Group=StreamConfig | Stream6
Hidden=1
Text=Image6: #StationImage6#
LeftMouseUpAction=[!CommandMeasure Measure-Input62 "ExecuteBatch 1-2"]
[Meter-Input63-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=-185r
Y=25r
W=355
Group=StreamConfig | Stream6
Hidden=1
Text=Stream6: #StationURL6#
LeftMouseUpAction=[!CommandMeasure Measure-Input63 "ExecuteBatch 1-2"]
[Meter-Input64-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=0r
Y=25r
W=355
Group=StreamConfig | Stream6
Hidden=1
Text=Tracklist6: #StationTrackListURL6#
LeftMouseUpAction=[!CommandMeasure Measure-Input64 "ExecuteBatch 1-2"]

[Measure-Input61]
Measure=Plugin
Plugin=InputText
FontSize=8
W=139
X=53
Y=230
H=14
Group=StreamConfig | Stream6
Hidden=1
FocusDismiss=0
DefaultValue=#StationTitle6#
Command1=[!SetVariable StationTitle6 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationTitle6" [Measure-Input61] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]
[Measure-Input62]
Measure=Plugin
Plugin=InputText
FontSize=8
W=129
X=248
Y=230
H=14
Group=StreamConfig | Stream6
Hidden=1
FocusDismiss=0
DefaultValue=#StationImage6#
Command1=[!SetVariable StationImage6 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationImage6" [Measure-Input62] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]
[Measure-Input63]
Measure=Plugin
Plugin=InputText
FontSize=8
W=310
X=67
Y=255
H=14
Group=StreamConfig | Stream6
Hidden=1
FocusDismiss=0
DefaultValue=#StationURL6#
Command1=[!SetVariable StationURL6 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationURL6" [Measure-Input63] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]
[Measure-Input64]
Measure=Plugin
Plugin=InputText
FontSize=8
W=305
X=72
Y=279
H=14
Group=StreamConfig | Stream6
Hidden=1
FocusDismiss=0
DefaultValue=#StationTrackListURL6#
Command1=[!SetVariable StationTrackListURL6 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationTrackListURL6" [Measure-Input64] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]

[Stream6_Image]
Meter=Image
ImageName=#@#Images\Stations\#StationImage6#
W=100
X=150
Y=320
Group=StreamConfig | Stream6
Hidden=1

;-- Stream 7 -------------------------------------------------------------------------------- 

[Meter-Input71-Background]
Meter=Shape
Shape=Rectangle 20,227,175,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input71 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream7
Hidden=1
[Meter-Input72-Background]
Meter=Shape
Shape=Rectangle 205,227,175,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input72 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream7
Hidden=1
[Meter-Input73-Background]
Meter=Shape
Shape=Rectangle 20,252,360,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input73 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream7
Hidden=1
[Meter-Input74-Background]
Meter=Shape
Shape=Rectangle 20,277,360,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input74 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream7
Hidden=1

[Meter-Input71-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=21
Y=230
W=175
Group=StreamConfig | Stream7
Hidden=1
Text=Title7: #StationTitle7#
LeftMouseUpAction=[!CommandMeasure Measure-Input71 "ExecuteBatch 1-2"]
[Meter-Input72-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=185r
Y=0r
W=175
Group=StreamConfig | Stream7
Hidden=1
Text=Image7: #StationImage7#
LeftMouseUpAction=[!CommandMeasure Measure-Input72 "ExecuteBatch 1-2"]
[Meter-Input73-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=-185r
Y=25r
W=355
Group=StreamConfig | Stream7
Hidden=1
Text=Stream7: #StationURL7#
LeftMouseUpAction=[!CommandMeasure Measure-Input73 "ExecuteBatch 1-2"]
[Meter-Input74-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=0r
Y=25r
W=355
Group=StreamConfig | Stream7
Hidden=1
Text=Tracklist7: #StationTrackListURL7#
LeftMouseUpAction=[!CommandMeasure Measure-Input74 "ExecuteBatch 1-2"]

[Measure-Input71]
Measure=Plugin
Plugin=InputText
FontSize=8
W=139
X=53
Y=230
H=14
Group=StreamConfig | Stream7
Hidden=1
FocusDismiss=0
DefaultValue=#StationTitle7#
Command1=[!SetVariable StationTitle7 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationTitle7" [Measure-Input71] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]
[Measure-Input72]
Measure=Plugin
Plugin=InputText
FontSize=8
W=129
X=248
Y=230
H=14
Group=StreamConfig | Stream7
Hidden=1
FocusDismiss=0
DefaultValue=#StationImage7#
Command1=[!SetVariable StationImage7 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationImage7" [Measure-Input72] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]
[Measure-Input73]
Measure=Plugin
Plugin=InputText
FontSize=8
W=310
X=67
Y=255
H=14
Group=StreamConfig | Stream7
Hidden=1
FocusDismiss=0
DefaultValue=#StationURL7#
Command1=[!SetVariable StationURL7 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationURL7" [Measure-Input73] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]
[Measure-Input74]
Measure=Plugin
Plugin=InputText
FontSize=8
W=305
X=72
Y=279
H=14
Group=StreamConfig | Stream7
Hidden=1
FocusDismiss=0
DefaultValue=#StationTrackListURL7#
Command1=[!SetVariable StationTrackListURL7 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationTrackListURL7" [Measure-Input74] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]

[Stream7_Image]
Meter=Image
ImageName=#@#Images\Stations\#StationImage7#
W=100
X=150
Y=320
Group=StreamConfig | Stream7
Hidden=1

;-- Stream 8 -------------------------------------------------------------------------------- 

[Meter-Input81-Background]
Meter=Shape
Shape=Rectangle 20,227,175,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input81 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream8
Hidden=1
[Meter-Input82-Background]
Meter=Shape
Shape=Rectangle 205,227,175,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input82 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream8
Hidden=1
[Meter-Input83-Background]
Meter=Shape
Shape=Rectangle 20,252,360,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input83 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream8
Hidden=1
[Meter-Input84-Background]
Meter=Shape
Shape=Rectangle 20,277,360,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Measure-Input84 "ExecuteBatch 1-2"]
Group=StreamConfig | Stream8
Hidden=1

[Meter-Input81-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=21
Y=230
W=175
Group=StreamConfig | Stream8
Hidden=1
Text=Title8: #StationTitle8#
LeftMouseUpAction=[!CommandMeasure Measure-Input81 "ExecuteBatch 1-2"]
[Meter-Input82-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=185r
Y=0r
W=175
Group=StreamConfig | Stream8
Hidden=1
Text=Image8: #StationImage8#
LeftMouseUpAction=[!CommandMeasure Measure-Input82 "ExecuteBatch 1-2"]
[Meter-Input83-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=-185r
Y=25r
W=355
Group=StreamConfig | Stream8
Hidden=1
Text=Stream8: #StationURL8#
LeftMouseUpAction=[!CommandMeasure Measure-Input83 "ExecuteBatch 1-2"]
[Meter-Input84-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=0r
Y=25r
W=355
Group=StreamConfig | Stream8
Hidden=1
Text=Tracklist8: #StationTrackListURL8#
LeftMouseUpAction=[!CommandMeasure Measure-Input84 "ExecuteBatch 1-2"]

[Measure-Input81]
Measure=Plugin
Plugin=InputText
FontSize=8
W=139
X=53
Y=230
H=14
Group=StreamConfig | Stream8
Hidden=1
FocusDismiss=0
DefaultValue=#StationTitle8#
Command1=[!SetVariable StationTitle8 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationTitle8" [Measure-Input81] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]
[Measure-Input82]
Measure=Plugin
Plugin=InputText
FontSize=8
W=129
X=248
Y=230
H=14
Group=StreamConfig | Stream8
Hidden=1
FocusDismiss=0
DefaultValue=#StationImage8#
Command1=[!SetVariable StationImage8 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationImage8" [Measure-Input82] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]
[Measure-Input83]
Measure=Plugin
Plugin=InputText
FontSize=8
W=310
X=67
Y=255
H=14
Group=StreamConfig | Stream8
Hidden=1
FocusDismiss=0
DefaultValue=#StationURL8#
Command1=[!SetVariable StationURL8 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationURL8" [Measure-Input83] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]
[Measure-Input84]
Measure=Plugin
Plugin=InputText
FontSize=8
W=305
X=72
Y=279
H=14
Group=StreamConfig | Stream8
Hidden=1
FocusDismiss=0
DefaultValue=#StationTrackListURL8#
Command1=[!SetVariable StationTrackListURL8 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "StationTrackListURL8" [Measure-Input84] "#@#Stations.inc"][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]

[Stream8_Image]
Meter=Image
ImageName=#@#Images\Stations\#StationImage8#
W=100
X=150
Y=320
Group=StreamConfig | Stream8
Hidden=1

;-- Help -------------------------------------------------------------------------------- 

[Help_Description]
Meter=String
MeterStyle=SettingsStyle-Text
X=20
Y=435
W=350
Text= - #VarStreamConfigHelp##CRLF##CRLF# - #VarStationImageHelp#
Clipstring=2

[Open_StreamImagesButton]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn350x25.png
X=25
Y=560
LeftMouseUpAction=["#@#Images\Stations\"]

[Open_StreamImages]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=200
Y=565
Text=#VarStationImages#

;-- VLC Config -------------------------------------------------------------------------------- 

[BG5]
Meter=Shape
Shape=Rectangle 10,615,380,120,3 | Fill Color 50,50,50

[T5Text]
Meter=String
MeterStyle=SettingsStyle-Text
Y=620
Text=#VarVLCPath#

[T5Divider]
Meter=Shape
Shape=Rectangle 12,635,350,2,0 | Fill Color 160,160,160

[VLC-Image]
Meter=Image
ImageName=#@#Images\General\VLC.png
W=20
X=361
Y=618

[VLC-Background]
Meter=Shape
Shape=Rectangle 20,655,360,20,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure VLC-Measure "ExecuteBatch 1-2"]

[VLC-CurrentValue]
Meter=String
MeterStyle=SettingsStyle-Input
X=21
Y=658
Text=#PathToVLC#
LeftMouseUpAction=[!CommandMeasure VLC-Measure "ExecuteBatch 1-2"]

[VLC-Measure]
Measure=Plugin
Plugin=InputText
FontSize=8
W=355
X=23
Y=658
H=14
FocusDismiss=0
DefaultValue=#PathToVLC#
Command1=[!SetVariable PathToVLC "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables "PathToVLC" [VLC-Measure] "#@#Stations.inc"]["#@#Tools\omnimoapp.exe" Radio Kill][!Refresh "#ROOTCONFIG#\Panels\Webradio"][!Refresh "#ROOTCONFIG#\Circles\Webradio"]


