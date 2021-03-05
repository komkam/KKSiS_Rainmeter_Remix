;---- Measures Volume ----

[VolumeWin]
Measure			=Plugin
Plugin			=Win7AudioPlugin
UpdateDivider	=1

[VolumeWinInverted]
Measure			=Plugin
InvertMeasure	=1
Plugin			=Win7AudioPlugin
UpdateDivider	=1

[VolumeWinPercent]
Measure			=Calc
Formula			=VolumeWin
UpdateDivider	=3
IfCondition		=(VolumeWinPercent = -1) && (#WRActive# = 1)
IfTrueAction	=[!ShowMeter "ButtonMute"][!HideMeter "ButtonVol"]
IfFalseAction	=[!HideMeter "ButtonMute"][!HideMeter "ButtonVol"]
IfCondition2	=(VolumeWinPercent > 0) && (#WRActive# = 1)
IfTrueAction2	=[!HideMeter "ButtonMute"][!ShowMeter "ButtonVol"]
DynamicVariables=1

[VolumeWinSmooth]
Measure			=Calc
Formula			=VolumeWinInverted
AverageSize		=6
UpdateDivider	=1

[FunctionSwitch]
Measure			=Calc
Formula			=#WRShowColoredBtnFrame#
IfCondition		=(#WRShowColoredBtnFrame# = 1)
IfTrueAction	=[!SetVariable CurrentBarColor #Circle-RoundlineFillColor1#]
DynamicVariables=1
Updatedivider	=1

;---- Measures Audiolevel ----

[WinAudioLevel]
Measure=Plugin
Plugin=AudioLevel
Port=Output
FFTSize=4096
FFTAttack=100
FFTDecay=100
Bands=135
UpdateDivier=1

[Band0]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=1

[Band1]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=1

[Band2]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=2

[Band3]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=3

[Band4]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=4

[Band5]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=5

[Band6]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=6

[Band7]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=7

[Band8]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=8

[Band9]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=9

[Band10]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=10

[Band11]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=11

[Band12]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=12

[Band13]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=13

[Band14]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=14

[Band15]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=15

[Band16]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=16

[Band17]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=17

[Band18]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=18

[Band19]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=19

[Band20]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=20

[Band21]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=21

[Band22]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=22

[Band23]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=23

[Band24]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=24

[Band25]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=25

[Band26]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=26

[Band27]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=27

[Band28]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=28

[Band29]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=29

[Band30]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=30

[Band31]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=31

[Band32]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=32

[Band33]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=33

[Band34]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=34

[Band35]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=35

[Band36]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=36

[Band37]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=37

[Band38]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=38

[Band39]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=39

[Band40]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=40

[Band41]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=41

[Band42]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=42

[Band43]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=43

[Band44]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=44

[Band45]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=45

[Band46]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=46

[Band47]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=47

[Band48]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=48

[Band49]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=49

[Band50]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=50

[Band51]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=51

[Band52]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=52

[Band53]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=53

[Band54]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=54

[Band55]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=55

[Band56]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=56

[Band57]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=57

[Band58]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=58

[Band59]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=59

[Band60]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=60

[Band61]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=61

[Band62]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=62

[Band63]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=63

[Band64]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=64

[Band65]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=65

[Band66]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=66

[Band67]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=67

[Band68]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=68

[Band69]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=69

[Band70]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=70

[Band71]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=71

[Band72]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=72

[Band73]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=73

[Band74]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=74

[Band75]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=75

[Band76]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=76

[Band77]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=77

[Band78]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=78

[Band79]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=79

[Band80]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=80

[Band81]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=81

[Band82]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=82

[Band83]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=83

[Band84]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=84

[Band85]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=85

[Band86]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=86

[Band87]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=87

[Band88]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=88

[Band89]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=89

[Band90]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=90

[Band91]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=91

[Band92]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=92

[Band93]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=93

[Band94]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=94

[Band95]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=95

[Band96]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=96

[Band97]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=97

[Band98]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=98

[Band99
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=99

[Band100]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=100

[Band101]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=101

[Band102]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=102

[Band103]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=103

[Band104]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=104

[Band105]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=105

[Band106]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=106

[Band107]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=107

[Band108]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=108

[Band109]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=109

[Band110]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=110

[Band111]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=111

[Band112]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=112

[Band113]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=113

[Band114]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=114

[Band115]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=115

[Band116]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=116

[Band117]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=117

[Band118]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=118

[Band119]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=119

[Band120]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=120

[Band121]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=121

[Band122]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=122

[Band123]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=123

[Band124]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=124

[Band125]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=125

[Band126]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=126

[Band127]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=127

[Band128]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=128

[Band129]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=129

[Band130]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=130

[Band131]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=131

[Band132]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=132

[Band133]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=133

[Band134]
Measure=Plugin
Plugin=AudioLevel
Parent=WinAudioLevel
Type=Band
BandIdx=134


;---- Roundline 0 - 100 ----

[Measure-Roundline-Left]
Meter=Roundline
MeterStyle=Roundline-Left
MeasureName=VolumeWinSmooth
ValueRemainder=100
Updatedivider=1

[Measure-Roundline-Right]
Meter=Roundline
MeterStyle=Roundline-Right
MeasureName=VolumeWinSmooth
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


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
LeftMouseUpAction=[!ShowMeterGroup Stations]
MouseScrollDownAction=[!CommandMeasure "VolumeWin" "ChangeVolume -3"]
MouseScrollUpAction=[!CommandMeasure "VolumeWin" "ChangeVolume +3"]
Updatedivider=-1


;---- Default Cover & Station ----

[SpeakerLogo]
	Meter=Image
	ImageName=#@#Images\General\Speaker.png
	X=(#CRadius#*0.6)
	Y=(#CRadius#*0.6)
	W=(#CRadius#*0.8)
	H=(#CRadius#*0.8)
	Hidden=#WRActive#
	Group=RadioOff
	DynamicVariables=1
	Updatedivider=-1

[Volume]
	Meter=String
	MeterStyle=CText | CSize6 | CCenter
	MeasureName=VolumeWinPercent
	Y=(#CRadius#*(1.44-#WRActive#*1.28))
	Group=RadioOff
	Hidden=#WRHideVolume#
	Text=Vol %1
	UpdateDivider=3
	DynamicVariables=1

[Title]
	Meter=String
	MeterStyle=CText | CTitle
	Text=Webradio
	Group=RadioOff
	Hidden=#WRActive#
	DynamicVariables=1
	Updatedivider=-1


;---- Active Cover & Station ----

[Cover]
	Meter=Image
	ImageName=#@#Images\Stations\#WRASImage#
	AntiAlias=1
	X=(#CRadius#*0.6)
	Y=(#CRadius#*0.6)
	W=(#CRadius#*0.8)
	H=(#CRadius#*0.8)
	Hidden=#WRInactive#
	Group=Radio
	LeftMouseUpAction=[#WRASTracklist#]
	DynamicVariables=1
	UpdateDivider=10
	Container=CoverContainer

[CoverContainer]
	Meter=Shape
	Shape=Rectangle (#CRadius#*0.6),(#CRadius#*0.6),(#CRadius#*0.8),(#CRadius#*0.8),(#CRadius#*0.4) | StrokeWidth 0 | Fill Color 0,0,0
	DynamicVariables=1

[SationText]
	Meter=String
	MeterStyle=CText | CTitle
	Hidden=#WRInactive#
	Group=Radio
	Text=#WRASTitle#
	UpdateDivider=10


;---- Buttons ----

[ButtonFrame]
	Meter=Shape
	Shape=Rectangle (#CRadius#*0.62),(#CRadius#*1.43),(#CRadius#*0.16),(#CRadius#*0.16),(#CRadius#*0.02) | StrokeWidth (#CRadius#*0.01) | Stroke LinearGradient ButtonFrameColor#WRShowColoredBtnFrame##Circle-RoundlineFillStyle# | Fill Color 0,0,0,0
	Shape2=Rectangle (#CRadius#*0.82),(#CRadius#*1.43),(#CRadius#*0.16),(#CRadius#*0.16),(#CRadius#*0.02) | StrokeWidth (#CRadius#*0.01) | Stroke LinearGradient ButtonFrameColor#WRShowColoredBtnFrame##Circle-RoundlineFillStyle# | Fill Color 0,0,0,0
	Shape3=Rectangle (#CRadius#*1.02),(#CRadius#*1.43),(#CRadius#*0.16),(#CRadius#*0.16),(#CRadius#*0.02) | StrokeWidth (#CRadius#*0.01) | Stroke LinearGradient ButtonFrameColor#WRShowColoredBtnFrame##Circle-RoundlineFillStyle# | Fill Color 0,0,0,0
	Shape4=Rectangle (#CRadius#*1.22),(#CRadius#*1.43),(#CRadius#*0.16),(#CRadius#*0.16),(#CRadius#*0.02) | StrokeWidth (#CRadius#*0.01) | Stroke LinearGradient ButtonFrameColor#WRShowColoredBtnFrame##Circle-RoundlineFillStyle#| Fill Color 0,0,0,0
	ButtonFrameColor01=90 | #Circle-ButtonColor# ; 0.0 | #Circle-ButtonColor# ; 1.0
	ButtonFrameColor02=90 | #Circle-ButtonColor# ; 0.0 | #Circle-ButtonColor# ; 1.0
	ButtonFrameColor03=90 | #Circle-ButtonColor# ; 0.0 | #Circle-ButtonColor# ; 1.0
	ButtonFrameColor11=90 | #Circle-RoundlineFillColor1# ; 0.0 | #Circle-RoundlineFillColor1# ; 1.0
	ButtonFrameColor12=90 | #Circle-RoundlineFillColor3# ; 0.0 |  #Circle-RoundlineFillColor1# ; 1.0
	ButtonFrameColor13=90 | #Circle-RoundlineFillColor3# ; 0.0 | #Circle-RoundlineFillColor2# ; 0.5 | #Circle-RoundlineFillColor1# ; 1.0
	DynamicVariables=1
	AntiAlias=1
	Hidden=#WRInactive#
	Group=Radio
	UpdateDivider=-1

[ButtonVol]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnVol.png
	ImageTint=#Circle-ButtonColor#
	X=(#CRadius#*0.652)	
	Y=(#CRadius#*1.462)	
	H=(#CRadius#*0.1)	
	W=(#CRadius#*0.1)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonVol ImageTint #Circle-RoundlineFillColor1#]
	MouseLeaveAction=[!SetOption ButtonVol ImageTint #Circle-ButtonColor#]
	LeftMouseUpAction=[!CommandMeasure "VolumeWin" "ToggleMute"]
	UpdateDivider=1

[ButtonMute]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnVolMute.png
	ImageTint=#Circle-ButtonColor#
	X=(#CRadius#*0.652)	
	Y=(#CRadius#*1.462)	
	H=(#CRadius#*0.1)	
	W=(#CRadius#*0.1)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonMute ImageTint #Circle-RoundlineFillColor1#]
	MouseLeaveAction=[!SetOption ButtonMute ImageTint #Circle-ButtonColor#]
	LeftMouseUpAction=[!CommandMeasure "VolumeWin" "ToggleMute"]
	UpdateDivider=1

[ButtonStop]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnStop.png
	ImageTint=#Circle-ButtonColor#
	X=(#CRadius#*0.852)	
	Y=(#CRadius#*1.462)	
	H=(#CRadius#*0.1)	
	W=(#CRadius#*0.1)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonStop ImageTint #Circle-RoundlineFillColor1#]
	MouseLeaveAction=[!SetOption ButtonStop ImageTint #Circle-ButtonColor#]
	LeftMouseUpAction=[!SetVariable "WRActive" "0"][!WriteKeyValue Variables "WRActive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "1" "#@#Variables.inc"]["#@#Tools\omnimoapp.exe" Radio Kill][!HideMeterGroup Radio][!ShowMeterGroup RadioOff][!Redraw]
	UpdateDivider=1

[ButtonPlay]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnPlay.png
	ImageTint=#Circle-ButtonColor#
	X=(#CRadius#*1.052)		
	Y=(#CRadius#*1.462)	
	H=(#CRadius#*0.1)	
	W=(#CRadius#*0.1)	
	Hidden=1
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonPlay ImageTint #Circle-RoundlineFillColor1#]
	MouseLeaveAction=[!SetOption ButtonPlay ImageTint #Circle-ButtonColor#]
	LeftMouseUpAction=["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#WRASStream#"][!HideMeter ButtonPlay][!ShowMeter ButtonPause]
	UpdateDivider=1

[ButtonPause]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnPause.png
	ImageTint=#Circle-ButtonColor#
	X=(#CRadius#*1.052)		
	Y=(#CRadius#*1.462)	
	H=(#CRadius#*0.1)	
	W=(#CRadius#*0.1)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonPause ImageTint #Circle-RoundlineFillColor1#]
	MouseLeaveAction=[!SetOption ButtonPause ImageTint #Circle-ButtonColor#]
	LeftMouseUpAction=["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" Off][!HideMeter ButtonPause][!ShowMeter ButtonPlay]
	UpdateDivider=1

[ButtonStations]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnStations.png
	ImageTint=#Circle-ButtonColor#
	X=(#CRadius#*1.252)		
	Y=(#CRadius#*1.462)	
	H=(#CRadius#*0.1)	
	W=(#CRadius#*0.1)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonStations ImageTint #Circle-RoundlineFillColor1#]
	MouseLeaveAction=[!SetOption ButtonStations ImageTint #Circle-ButtonColor#]
	LeftMouseUpAction=[!ShowMeterGroup Stations]
	UpdateDivider=1


;---- Audiolevelmeter ----

[StyleAudioBar]
	Flip=0
	BarColor=#CurrentBarColor#
	SolidColor=0,0,0,0
	BarOrientation=Vertical
	X=0
	Y=0
	W=(#CRadius#*0.013)
	H=(#CRadius#*0.32)
	AntiAlias=1
	DynamicVariables=1
	UpdateDivider=1
	;Group=Radio
	;Hidden=#WRInactive#
	
[MeterBand_0]
Meter=Bar
MeterStyle=StyleAudiobar
MeasureName=Band0
TransformationMatrix=0.69465837;0.7193398;-0.7193398;0.69465837;(#CRadius#*0.71226407986454);(#Cradius#*1.2778633481836)
[MeterBand_1]
Meter=Bar
MeasureName=Band1
MeterStyle=StyleAudiobar
TransformationMatrix=0.66909169;0.74317986;-0.74317986;0.66909169;(#CRadius#*0.702728055977875);(#Cradius#*1.26763667778783)
[MeterBand_2]
Meter=Bar
MeasureName=Band2
MeterStyle=StyleAudiobar
TransformationMatrix=0.64270739;0.76611175;-0.76611175;0.64270739;(#CRadius#*0.693555299408149);(#Cradius#*1.25708295447029)
[MeterBand_3]
Meter=Bar
MeasureName=Band3
MeterStyle=StyleAudiobar
TransformationMatrix=0.61553769;0.78810745;-0.78810745;0.61553769;(#CRadius#*0.684757019294788);(#Cradius#*1.24621507491641)
[MeterBand_4]
Meter=Bar
MeasureName=Band4
MeterStyle=StyleAudiobar
TransformationMatrix=0.5876158;0.80914008;-0.80914008;0.5876158;(#CRadius#*0.676343967165726);(#Cradius#*1.23504631971162)
[MeterBand_5]
Meter=Bar
MeasureName=Band5
MeterStyle=StyleAudiobar
TransformationMatrix=0.55897584;0.82918394;-0.82918394;0.55897584;(#CRadius#*0.668326423799004);(#Cradius#*1.22359033711241)
[MeterBand_6]
Meter=Bar
MeasureName=Band6
MeterStyle=StyleAudiobar
TransformationMatrix=0.52965282;0.84821453;-0.84821453;0.52965282;(#CRadius#*0.660714186659623);(#Cradius#*1.2118611263681)
[MeterBand_7]
Meter=Bar
MeasureName=Band7
MeterStyle=StyleAudiobar
TransformationMatrix=0.49968255;0.86620861;-0.86620861;0.49968255;(#CRadius#*0.653516557927009);(#Cradius#*1.19987302061372)
[MeterBand_8]
Meter=Bar
MeasureName=Band8
MeterStyle=StyleAudiobar
TransformationMatrix=0.46910167;0.88314417;-0.88314417;0.46910167;(#CRadius#*0.646742333127717);(#Cradius#*1.18764066935489)
[MeterBand_9]
Meter=Bar
MeasureName=Band9
MeterStyle=StyleAudiobar
TransformationMatrix=0.43794755;0.89900052;-0.89900052;0.43794755;(#CRadius#*0.640399790387271);(#Cradius#*1.17517902056605)
[MeterBand_10]
Meter=Bar
MeasureName=Band10
MeterStyle=StyleAudiobar
TransformationMatrix=0.40625826;0.9137583;-0.9137583;0.40625826;(#CRadius#*0.634496680314264);(#Cradius#*1.162503302424)
[MeterBand_11]
Meter=Bar
MeasureName=Band11
MeterStyle=StyleAudiobar
TransformationMatrix=0.37407251;0.92739946;-0.92739946;0.37407251;(#CRadius#*0.62904021652909);(#Cradius#*1.14962900469901)
[MeterBand_12]
Meter=Bar
MeasureName=Band12
MeterStyle=StyleAudiobar
TransformationMatrix=0.34142965;0.93990733;-0.93990733;0.34142965;(#CRadius#*0.624037066848874);(#Cradius#*1.13657185982625)
[MeterBand_13]
Meter=Bar
MeasureName=Band13
MeterStyle=StyleAudiobar
TransformationMatrix=0.30836956;0.95126664;-0.95126664;0.30836956;(#CRadius#*0.619493345139378);(#Cradius#*1.12334782368076)
[MeterBand_14]
Meter=Bar
MeasureName=Band14
MeterStyle=StyleAudiobar
TransformationMatrix=0.27493264;0.96146349;-0.96146349;0.27493264;(#CRadius#*0.615414603843836);(#Cradius#*1.10997305607923)
[MeterBand_15]
Meter=Bar
MeasureName=Band15
MeterStyle=StyleAudiobar
TransformationMatrix=0.24115975;0.97048543;-0.97048543;0.24115975;(#CRadius#*0.61180582719785);(#Cradius#*1.09646390103274)
[MeterBand_16]
Meter=Bar
MeasureName=Band16
MeterStyle=StyleAudiobar
TransformationMatrix=0.20709217;0.97832144;-0.97832144;0.20709217;(#CRadius#*0.608671425138639);(#Cradius#*1.08283686677426)
[MeterBand_17]
Meter=Bar
MeasureName=Band17
MeterStyle=StyleAudiobar
TransformationMatrix=0.17277151;0.98496193;-0.98496193;0.17277151;(#CRadius#*0.606015227916076);(#Cradius#*1.06910860558554)
[MeterBand_18]
Meter=Bar
MeasureName=Band18
MeterStyle=StyleAudiobar
TransformationMatrix=0.13823973;0.9903988;-0.9903988;0.13823973;(#CRadius#*0.603840481412114);(#Cradius#*1.05529589344801)
[MeterBand_19]
Meter=Bar
MeasureName=Band19
MeterStyle=StyleAudiobar
TransformationMatrix=0.10353902;0.99462539;-0.99462539;0.10353902;(#CRadius#*0.602149843174307);(#Cradius#*1.04141560954243)
[MeterBand_20]
Meter=Bar
MeasureName=Band20
MeterStyle=StyleAudiobar
TransformationMatrix=0.06871179;0.99763655;-0.99763655;0.06871179;(#CRadius#*0.600945379168276);(#Cradius#*1.02748471562248)
[MeterBand_21]
Meter=Bar
MeasureName=Band21
MeterStyle=StyleAudiobar
TransformationMatrix=0.03380059;0.9994286;-0.9994286;0.03380059;(#CRadius#*0.600228561253093);(#Cradius#*1.01352023528746)
[MeterBand_22]
Meter=Bar
MeasureName=Band22
MeterStyle=StyleAudiobar
TransformationMatrix=-0.00115192;0.99999934;-0.99999934;-0.00115192;(#CRadius#*0.600000265382667);(#Cradius#*0.999539233179375)
[MeterBand_23]
Meter=Bar
MeasureName=Band23
MeterStyle=StyleAudiobar
TransformationMatrix=-0.03610301;0.99934807;-0.99934807;-0.03610301;(#CRadius#*0.600260770535318);(#Cradius#*0.985558794129897)
[MeterBand_24]
Meter=Bar
MeasureName=Band24
MeterStyle=StyleAudiobar
TransformationMatrix=-0.07100999;0.9974756;-0.9974756;-0.07100999;(#CRadius#*0.601009758372874);(#Cradius#*0.971596002282637)
[MeterBand_25]
Meter=Bar
MeasureName=Band25
MeterStyle=StyleAudiobar
TransformationMatrix=-0.1058302;0.99438422;-0.99438422;-0.1058302;(#CRadius#*0.602246313629674);(#Cradius#*0.957667920216265)
[MeterBand_26]
Meter=Bar
MeasureName=Band26
MeterStyle=StyleAudiobar
TransformationMatrix=-0.14052108;0.99007769;-0.99007769;-0.14052108;(#CRadius#*0.603968925231029);(#Cradius#*0.943791568093981)
[MeterBand_27]
Meter=Bar
MeasureName=Band27
MeterStyle=StyleAudiobar
TransformationMatrix=-0.17504024;0.98456128;-0.98456128;-0.17504024;(#CRadius#*0.606175488139759);(#Cradius#*0.929983902864821)
[MeterBand_28]
Meter=Bar
MeasureName=Band28
MeterStyle=StyleAudiobar
TransformationMatrix=-0.20934551;0.97784174;-0.97784174;-0.20934551;(#CRadius#*0.608863305928557);(#Cradius#*0.916261797542206)
[MeterBand_29]
Meter=Bar
MeasureName=Band29
MeterStyle=StyleAudiobar
TransformationMatrix=-0.24339495;0.96992726;-0.96992726;-0.24339495;(#CRadius#*0.612029094075032);(#Cradius#*0.902642020585062)
[MeterBand_30]
Meter=Bar
MeasureName=Band30
MeterStyle=StyleAudiobar
TransformationMatrix=-0.27714696;0.96082754;-0.96082754;-0.27714696;(#CRadius#*0.615668983975404);(#Cradius#*0.889141215406707)
[MeterBand_31]
Meter=Bar
MeasureName=Band31
MeterStyle=StyleAudiobar
TransformationMatrix=-0.3105603;0.95055368;-0.95055368;-0.3105603;(#CRadius#*0.619778527671956);(#Cradius#*0.875775880036546)
[MeterBand_32]
Meter=Bar
MeasureName=Band32
MeterStyle=StyleAudiobar
TransformationMatrix=-0.34359413;0.93911824;-0.93911824;-0.34359413;(#CRadius#*0.624352703288446);(#Cradius#*0.862562346959423)
[MeterBand_33]
Meter=Bar
MeasureName=Band33
MeterStyle=StyleAudiobar
TransformationMatrix=-0.37620809;0.9265352;-0.9265352;-0.37620809;(#CRadius#*0.629385921166864);(#Cradius#*0.849516763157266)
[MeterBand_34]
Meter=Bar
MeasureName=Band34
MeterStyle=StyleAudiobar
TransformationMatrix=-0.40836232;0.91281992;-0.91281992;-0.40836232;(#CRadius#*0.634872030698008);(#Cradius#*0.836655070377425)
[MeterBand_35]
Meter=Bar
MeasureName=Band35
MeterStyle=StyleAudiobar
TransformationMatrix=-0.44001754;0.89798918;-0.89798918;-0.44001754;(#CRadius#*0.640804327837552);(#Cradius#*0.823992985651801)
[MeterBand_36]
Meter=Bar
MeasureName=Band36
MeterStyle=StyleAudiobar
TransformationMatrix=-0.47113504;0.88206109;-0.88206109;-0.47113504;(#CRadius#*0.647175563298408);(#Cradius#*0.81154598209058)
[MeterBand_37]
Meter=Bar
MeasureName=Band37
MeterStyle=StyleAudiobar
TransformationMatrix=-0.50167683;0.86505512;-0.86505512;-0.50167683;(#CRadius#*0.653977951409382);(#Cradius#*0.79932926997404)
[MeterBand_38]
Meter=Bar
MeasureName=Band38
MeterStyle=StyleAudiobar
TransformationMatrix=-0.53160555;0.84699205;-0.84699205;-0.53160555;(#CRadius#*0.661203179629288);(#Cradius#*0.78735777816554)
[MeterBand_39]
Meter=Bar
MeasureName=Band39
MeterStyle=StyleAudiobar
TransformationMatrix=-0.56088466;0.82789395;-0.82789395;-0.56088466;(#CRadius#*0.668842418704906);(#Cradius#*0.775646135868394)
[MeterBand_40]
Meter=Bar
MeasureName=Band40
MeterStyle=StyleAudiobar
TransformationMatrix=-0.58947836;0.80778417;-0.80778417;-0.58947836;(#CRadius#*0.676886333460351);(#Cradius#*0.764208654748941)
[MeterBand_41]
Meter=Bar
MeasureName=Band41
MeterStyle=StyleAudiobar
TransformationMatrix=-0.61735172;0.78668726;-0.78668726;-0.61735172;(#CRadius#*0.685325094204697);(#Cradius#*0.753059311447633)
[MeterBand_42]
Meter=Bar
MeasureName=Band42
MeterStyle=StyleAudiobar
TransformationMatrix=-0.64447067;0.76462903;-0.76462903;-0.64447067;(#CRadius#*0.694148388743889);(#Cradius#*0.742211730499542)
[MeterBand_43]
Meter=Bar
MeasureName=Band43
MeterStyle=StyleAudiobar
TransformationMatrix=-0.67080208;0.74163641;-0.74163641;-0.67080208;(#CRadius#*0.703345434982279);(#Cradius#*0.731679167685126)
[MeterBand_44]
Meter=Bar
MeasureName=Band44
MeterStyle=StyleAudiobar
TransformationMatrix=-0.69631377;0.71773751;-0.71773751;-0.69631377;(#CRadius#*0.712904994098385);(#Cradius#*0.721474493831621)
[MeterBand_45]
Meter=Bar
MeasureName=Band45
MeterStyle=StyleAudiobar
TransformationMatrix=-0.72097455;0.69296154;-0.69296154;-0.72097455;(#CRadius#*0.722815384278766);(#Cradius#*0.711610179084851)
[MeterBand_46]
Meter=Bar
MeasureName=Band46
MeterStyle=StyleAudiobar
TransformationMatrix=-0.74475431;0.66733876;-0.66733876;-0.74475431;(#CRadius#*0.733064494993238);(#Cradius#*0.702098277670664)
[MeterBand_47]
Meter=Bar
MeasureName=Band47
MeterStyle=StyleAudiobar
TransformationMatrix=-0.76762397;0.6409005;-0.6409005;-0.76762397;(#CRadius#*0.743639801793985);(#Cradius#*0.692950413164628)
[MeterBand_48]
Meter=Bar
MeasureName=Band48
MeterStyle=StyleAudiobar
TransformationMatrix=-0.78955559;0.61367905;-0.61367905;-0.78955559;(#CRadius#*0.754528381620475);(#Cradius#*0.684177764287983)
[MeterBand_49
Meter=Bar
MeasureName=Band49
MeterStyle=StyleAudiobar
TransformationMatrix=-0.81052237;0.58570768;-0.58570768;-0.81052237;(#CRadius#*0.765716928591481);(#Cradius#*0.675791051247208)
[MeterBand_50]
Meter=Bar
MeasureName=Band50
MeterStyle=StyleAudiobar
TransformationMatrix=-0.83049869;0.55702057;-0.55702057;-0.83049869;(#CRadius#*0.777191770264917);(#Cradius#*0.667800522633887)
[MeterBand_51]
Meter=Bar
MeasureName=Band51
MeterStyle=StyleAudiobar
TransformationMatrix=-0.84946014;0.52765279;-0.52765279;-0.84946014;(#CRadius#*0.788938884345607);(#Cradius#*0.660215942900902)
[MeterBand_52]
Meter=Bar
MeasureName=Band52
MeterStyle=StyleAudiobar
TransformationMatrix=-0.86738355;0.49764021;-0.49764021;-0.86738355;(#CRadius#*0.800943915820572);(#Cradius#*0.653046580430236)
[MeterBand_53]
Meter=Bar
MeasureName=Band53
MeterStyle=StyleAudiobar
TransformationMatrix=-0.88424701;0.46701951;-0.46701951;-0.88424701;(#CRadius#*0.813192194500915);(#Cradius#*0.646301196206976)
[MeterBand_54]
Meter=Bar
MeasureName=Band54
MeterStyle=StyleAudiobar
TransformationMatrix=-0.90002992;0.43582812;-0.43582812;-0.90002992;(#CRadius#*0.825668752948828);(#Cradius#*0.639988033113365)
[MeterBand_55]
Meter=Bar
MeasureName=Band55
MeterStyle=StyleAudiobar
TransformationMatrix=-0.91471299;0.40410414;-0.40410414;-0.91471299;(#CRadius#*0.838358344767862);(#Cradius#*0.63411480585597)
[MeterBand_56]
Meter=Bar
MeasureName=Band56
MeterStyle=StyleAudiobar
TransformationMatrix=-0.92827827;0.37188634;-0.37188634;-0.92827827;(#CRadius#*0.851245463234071);(#Cradius#*0.628688691538281)
[MeterBand_57]
Meter=Bar
MeasureName=Band57
MeterStyle=StyleAudiobar
TransformationMatrix=-0.9407092;0.3392141;-0.3392141;-0.9407092;(#CRadius#*0.864314360245279);(#Cradius#*0.623716320890273)
[MeterBand_58]
Meter=Bar
MeasureName=Band58
MeterStyle=StyleAudiobar
TransformationMatrix=-0.95199057;0.30612734;-0.30612734;-0.95199057;(#CRadius#*0.877549065565316);(#Cradius#*0.619203770165627)
[MeterBand_59]
Meter=Bar
MeasureName=Band59
MeterStyle=StyleAudiobar
TransformationMatrix=-0.96210862;0.27266648;-0.27266648;-0.96210862;(#CRadius#*0.890933406339701);(#Cradius#*0.615156553716528)
[MeterBand_60]
Meter=Bar
MeasureName=Band60
MeterStyle=StyleAudiobar
TransformationMatrix=-0.97105096;0.23887243;-0.23887243;-0.97105096;(#CRadius#*0.904451026858924);(#Cradius#*0.611579617255111)
[MeterBand_61]
Meter=Bar
MeasureName=Band61
MeterStyle=StyleAudiobar
TransformationMatrix=-0.97880667;0.20478648;-0.20478648;-0.97880667;(#CRadius#*0.918085408545176);(#Cradius#*0.60847733180978)
[MeterBand_62]
Meter=Bar
MeasureName=Band62
MeterStyle=StyleAudiobar
TransformationMatrix=-0.98536628;0.17045027;-0.17045027;-0.98536628;(#CRadius#*0.931819890138111);(#Cradius#*0.605853488383798)
[MeterBand_63]
Meter=Bar
MeasureName=Band63
MeterStyle=StyleAudiobar
TransformationMatrix=-0.99072177;0.13590578;-0.13590578;-0.99072177;(#CRadius#*0.945637688054957);(#Cradius#*0.603711293322671)
[MeterBand_64]
Meter=Bar
MeasureName=Band64
MeterStyle=StyleAudiobar
TransformationMatrix=-0.99486659;0.10119521;-0.10119521;-0.99486659;(#CRadius#*0.959521916900117);(#Cradius#*0.60205336439598)
[MeterBand_65]
Meter=Bar
MeasureName=Band65
MeterStyle=StyleAudiobar
TransformationMatrix=-0.99779568;0.06636097;-0.06636097;-0.99779568;(#CRadius#*0.973455610099173);(#Cradius#*0.600881727598456)
[MeterBand_66]
Meter=Bar
MeasureName=Band66
MeterStyle=StyleAudiobar
TransformationMatrix=-0.99950546;0.03144565;-0.03144565;-0.99950546;(#CRadius#*0.987421740632101);(#Cradius#*0.600197814674214)
[MeterBand_67]
Meter=Bar
MeasureName=Band67
MeterStyle=StyleAudiobar
TransformationMatrix=-0.99999385;-0.0035081;0.0035081;-0.99999385;(#CRadius#*1.00140324184035);(#Cradius#*0.600002461367151)
[MeterBand_68]
Meter=Bar
MeasureName=Band68
MeterStyle=StyleAudiobar
TransformationMatrix=-0.99926023;-0.03845757;0.03845757;-0.99926023;(#CRadius#*1.01538302828233);(#Cradius#*0.600295906399666)
[MeterBand_69]
Meter=Bar
MeasureName=Band69
MeterStyle=StyleAudiobar
TransformationMatrix=-0.99730552;-0.07336004;0.07336004;-0.99730552;(#CRadius#*1.02934401661195);(#Cradius#*0.60107779118094)
[MeterBand_70]
Meter=Bar
MeasureName=Band70
MeterStyle=StyleAudiobar
TransformationMatrix=-0.9941321;-0.10817287;0.10817287;-0.9941321;(#CRadius#*1.04326914645441);(#Cradius#*0.602347160245137)
[MeterBand_71]
Meter=Bar
MeasureName=Band71
MeterStyle=StyleAudiobar
TransformationMatrix=-0.98974384;-0.1428535;0.1428535;-0.98974384;(#CRadius#*1.05714140125416);(#Cradius#*0.604102462418986)
[MeterBand_72]
Meter=Bar
MeasureName=Band72
MeterStyle=StyleAudiobar
TransformationMatrix=-0.98414612;-0.17735957;0.17735957;-0.98414612;(#CRadius#*1.0709438290691);(#Cradius#*0.606341552717316)
[MeterBand_73]
Meter=Bar
MeasureName=Band73
MeterStyle=StyleAudiobar
TransformationMatrix=-0.97734576;-0.21164891;0.21164891;-0.97734576;(#CRadius#*1.08465956328595);(#Cradius#*0.609061694964241)
[MeterBand_74]
Meter=Bar
MeasureName=Band74
MeterStyle=StyleAudiobar
TransformationMatrix=-0.96935109;-0.24567961;0.24567961;-0.96935109;(#CRadius#*1.09827184323129);(#Cradius#*0.612259565136774)
[MeterBand_75]
Meter=Bar
MeasureName=Band75
MeterStyle=StyleAudiobar
TransformationMatrix=-0.96017186;-0.27941009;0.27941009;-0.96017186;(#CRadius#*1.11176403465318);(#Cradius#*0.61593125542679)
[MeterBand_76]
Meter=Bar
MeasureName=Band76
MeterStyle=StyleAudiobar
TransformationMatrix=-0.9498193;-0.31279913;0.31279913;-0.9498193;(#CRadius#*1.12511965004826);(#Cradius#*0.620072279016388)
[MeterBand_77]
Meter=Bar
MeasureName=Band77
MeterStyle=StyleAudiobar
TransformationMatrix=-0.93830606;-0.34580592;0.34580592;-0.93830606;(#CRadius#*1.13832236880951);(#Cradius#*0.624677575560792)
[MeterBand_78]
Meter=Bar
MeasureName=Band78
MeterStyle=StyleAudiobar
TransformationMatrix=-0.92564621;-0.37839014;0.37839014;-0.92564621;(#CRadius#*1.15135605717015);(#Cradius#*0.629741517372113)
[MeterBand_79]
Meter=Bar
MeasureName=Band79
MeterStyle=StyleAudiobar
TransformationMatrix=-0.91185521;-0.41051197;0.41051197;-0.91185521;(#CRadius#*1.1642047879191);(#Cradius#*0.6352579162964)
[MeterBand_80]
Meter=Bar
MeasureName=Band80
MeterStyle=StyleAudiobar
TransformationMatrix=-0.89694992;-0.44213215;0.44213215;-0.89694992;(#CRadius#*1.17685285986409);(#Cradius#*0.641220031275585)
[MeterBand_81]
Meter=Bar
MeasureName=Band81
MeterStyle=StyleAudiobar
TransformationMatrix=-0.88094856;-0.47321204;0.47321204;-0.88094856;(#CRadius#*1.18928481701861);(#Cradius#*0.64762057658508)
[MeterBand_82]
Meter=Bar
MeasureName=Band82
MeterStyle=StyleAudiobar
TransformationMatrix=-0.86387067;-0.50371367;0.50371367;-0.86387067;(#CRadius#*1.20148546748914);(#Cradius#*0.654451730736959)
[MeterBand_83]
Meter=Bar
MeasureName=Band83
MeterStyle=StyleAudiobar
TransformationMatrix=-0.84573713;-0.53359976;0.53359976;-0.84573713;(#CRadius#*1.2134399020397);(#Cradius#*0.661705146037835)
[MeterBand_84]
Meter=Bar
MeasureName=Band84
MeterStyle=StyleAudiobar
TransformationMatrix=-0.8265701;-0.56283378;0.56283378;-0.8265701;(#CRadius#*1.22513351231101);(#Cradius#*0.669371958789781)
[MeterBand_85]
Meter=Bar
MeasureName=Band85
MeterStyle=StyleAudiobar
TransformationMatrix=-0.806393;-0.59138002;0.59138002;-0.806393;(#CRadius#*1.23655200867193);(#Cradius#*0.677442800121787)
[MeterBand_86]
Meter=Bar
MeasureName=Band86
MeterStyle=StyleAudiobar
TransformationMatrix=-0.78523048;-0.61920359;0.61920359;-0.78523048;(#CRadius#*1.24768143768144);(#Cradius#*0.685907807438559)
[MeterBand_87]
Meter=Bar
MeasureName=Band87
MeterStyle=StyleAudiobar
TransformationMatrix=-0.76310841;-0.6462705;0.6462705;-0.76310841;(#CRadius#*1.25850819913981);(#Cradius#*0.694756636472642)
[MeterBand_88]
Meter=Bar
MeasureName=Band88
MeterStyle=StyleAudiobar
TransformationMatrix=-0.74005382;-0.67254766;0.67254766;-0.74005382;(#CRadius#*1.26901906270805);(#Cradius#*0.703978473925151)
[MeterBand_89]
Meter=Bar
MeasureName=Band89
MeterStyle=StyleAudiobar
TransformationMatrix=-0.71609487;-0.69800296;0.69800296;-0.71609487;(#CRadius#*1.27920118407549);(#Cradius#*0.713562050679654)
[MeterBand_90]
Meter=Bar
MeasureName=Band90
MeterStyle=StyleAudiobar
TransformationMatrix=-0.69126086;-0.7226053;0.7226053;-0.69126086;(#CRadius#*1.28904212065552);(#Cradius#*0.723495655573077)
[MeterBand_91]
Meter=Bar
MeasureName=Band91
MeterStyle=StyleAudiobar
TransformationMatrix=-0.66558213;-0.74632462;0.74632462;-0.66558213;(#CRadius#*1.29852984679048);(#Cradius#*0.733767149706778)
[MeterBand_92]
Meter=Bar
MeasureName=Band92
MeterStyle=StyleAudiobar
TransformationMatrix=-0.63909005;-0.76913192;0.76913192;-0.63909005;(#CRadius#*1.30765276844708);(#Cradius#*0.744363981280327)
[MeterBand_93]
Meter=Bar
MeasureName=Band93
MeterStyle=StyleAudiobar
TransformationMatrix=-0.611817;-0.79099934;0.79099934;-0.611817;(#CRadius#*1.31639973738434);(#Cradius#*0.755273200929847)
[MeterBand_94]
Meter=Bar
MeasureName=Band94
MeterStyle=StyleAudiobar
TransformationMatrix=-0.58379631;-0.81190016;0.81190016;-0.58379631;(#CRadius#*1.32476006477673);(#Cradius#*0.766481477552179)
[MeterBand_95]
Meter=Bar
MeasureName=Band95
MeterStyle=StyleAudiobar
TransformationMatrix=-0.55506221;-0.83180884;0.83180884;-0.55506221;(#CRadius#*1.33272353427603);(#Cradius#*0.777975114595535)
[MeterBand_96]
Meter=Bar
MeasureName=Band96
MeterStyle=StyleAudiobar
TransformationMatrix=-0.52564983;-0.85070104;0.85070104;-0.52564983;(#CRadius#*1.34028041449569);(#Cradius#*0.789740066796734)
[MeterBand_97]
Meter=Bar
MeasureName=Band97
MeterStyle=StyleAudiobar
TransformationMatrix=-0.49559511;-0.86855368;0.86855368;-0.49559511;(#CRadius#*1.34742147090262);(#Cradius#*0.801761957344555)
[MeterBand_98]
Meter=Bar
MeasureName=Band98
MeterStyle=StyleAudiobar
TransformationMatrix=-0.46493476;-0.88534494;0.88534494;-0.46493476;(#CRadius#*1.35413797710183);(#Cradius#*0.814026095448255)
[MeterBand_99]
Meter=Bar
MeasureName=Band99
MeterStyle=StyleAudiobar
TransformationMatrix=-0.43370626;-0.90105431;0.90105431;-0.43370626;(#CRadius#*1.36042172550014);(#Cradius#*0.82651749428976)
[MeterBand_100]
Meter=Bar
MeasureName=Band100
MeterStyle=StyleAudiobar
TransformationMatrix=-0.40194778;-0.91566259;0.91566259;-0.40194778;(#CRadius#*1.36626503733582);(#Cradius#*0.839220889337608)
[MeterBand_101]
Meter=Bar
MeasureName=Band101
MeterStyle=StyleAudiobar
TransformationMatrix=-0.36969811;-0.92915193;0.92915193;-0.36969811;(#CRadius#*1.37166077206214);(#Cradius#*0.85212075700026)
[MeterBand_102]
Meter=Bar
MeasureName=Band102
MeterStyle=StyleAudiobar
TransformationMatrix=-0.33699667;-0.94150584;0.94150584;-0.33699667;(#CRadius#*1.37660233607308);(#Cradius#*0.865201333595981)
[MeterBand_103]
Meter=Bar
MeasureName=Band103
MeterStyle=StyleAudiobar
TransformationMatrix=-0.30388341;-0.95270923;0.95270923;-0.30388341;(#CRadius#*1.38108369076077);(#Cradius#*0.878446634616109)
[MeterBand_104]
Meter=Bar
MeasureName=Band104
MeterStyle=StyleAudiobar
TransformationMatrix=-0.27039881;-0.9627484;0.9627484;-0.27039881;(#CRadius#*1.3850993598947);(#Cradius#*0.891840474258182)
[MeterBand_105]
Meter=Bar
MeasureName=Band105
MeterStyle=StyleAudiobar
TransformationMatrix=-0.23658379;-0.97161109;0.97161109;-0.23658379;(#CRadius#*1.38864443631365);(#Cradius#*0.90536648520504)
[MeterBand_106]
Meter=Bar
MeasureName=Band106
MeterStyle=StyleAudiobar
TransformationMatrix=-0.20247965;-0.97928647;0.97928647;-0.20247965;(#CRadius#*1.3917145879223);(#Cradius#*0.919008138625746)
[MeterBand_107]
Meter=Bar
MeasureName=Band107
MeterStyle=StyleAudiobar
TransformationMatrix=-0.16812809;-0.98576516;0.98576516;-0.16812809;(#CRadius#*1.39430606298503);(#Cradius#*0.932748764373867)
[MeterBand_108]
Meter=Bar
MeasureName=Band108
MeterStyle=StyleAudiobar
TransformationMatrix=-0.13357107;-0.99103924;0.99103924;-0.13357107;(#CRadius#*1.39641569471061);(#Cradius#*0.946571571358455)
[MeterBand_109]
Meter=Bar
MeasureName=Band109
MeterStyle=StyleAudiobar
TransformationMatrix=-0.09885083;-0.99510226;0.99510226;-0.09885083;(#CRadius#*1.39804090512194);(#Cradius#*0.960459668062813)
[MeterBand_110]
Meter=Bar
MeasureName=Band110
MeterStyle=StyleAudiobar
TransformationMatrix=-0.06400979;-0.99794927;0.99794927;-0.06400979;(#CRadius#*1.39917970820644);(#Cradius#*0.974396083185989)
[MeterBand_111]
Meter=Bar
MeasureName=Band111
MeterStyle=StyleAudiobar
TransformationMatrix=-0.02909053;-0.99957678;0.99957678;-0.02909053;(#CRadius#*1.3998307123429);(#Cradius#*0.988363786381756)
[MeterBand_112]
Meter=Bar
MeasureName=Band112
MeterStyle=StyleAudiobar
TransformationMatrix=0.00586427;-0.99998281;0.99998281;0.00586427;(#CRadius#*1.39999312200207);(#Cradius#*1.00234570906976)
[MeterBand_113]
Meter=Bar
MeasureName=Band113
MeterStyle=StyleAudiobar
TransformationMatrix=0.04081191;-0.99916685;0.99916685;0.04081191;(#CRadius#*1.39966673871879);(#Cradius#*1.01632476529338)
[MeterBand_114]
Meter=Bar
MeasureName=Band114
MeterStyle=StyleAudiobar
TransformationMatrix=0.07570968;-0.9971299;0.9971299;0.07570968;(#CRadius#*1.39885196133455);(#Cradius#*1.03028387259882)
[MeterBand_115]
Meter=Bar
MeasureName=Band115
MeterStyle=StyleAudiobar
TransformationMatrix=0.11051493;-0.99387446;0.99387446;0.11051493;(#CRadius#*1.39754978551005);(#Cradius#*1.04420597290994)
[MeterBand_116]
Meter=Bar
MeasureName=Band116
MeterStyle=StyleAudiobar
TransformationMatrix=0.14518513;-0.98940451;0.98940451;0.14518513;(#CRadius#*1.39576180250853);(#Cradius#*1.05807405337326)
[MeterBand_117]
Meter=Bar
MeasureName=Band117
MeterStyle=StyleAudiobar
TransformationMatrix=0.17967792;-0.98372549;0.98372549;0.17967792;(#CRadius#*1.39349019725124);(#Cradius#*1.07187116714773)
[MeterBand_118]
Meter=Bar
MeasureName=Band118
MeterStyle=StyleAudiobar
TransformationMatrix=0.21395114;-0.97684436;0.97684436;0.21395114;(#CRadius#*1.39073774564747);(#Cradius#*1.08558045411386)
[MeterBand_119]
Meter=Bar
MeasureName=Band119
MeterStyle=StyleAudiobar
TransformationMatrix=0.2479629;-0.96876953;0.96876953;0.2479629;(#CRadius#*1.38750781120233);(#Cradius#*1.09918516147678)
[MeterBand_120]
Meter=Bar
MeasureName=Band120
MeterStyle=StyleAudiobar
TransformationMatrix=0.28167166;-0.95951085;0.95951085;0.28167166;(#CRadius#*1.38380434090661);(#Cradius#*1.11266866423829)
[MeterBand_121]
Meter=Bar
MeasureName=Band121
MeterStyle=StyleAudiobar
TransformationMatrix=0.31503621;-0.94907965;0.94907965;0.31503621;(#CRadius#*1.37963186041348);(#Cradius#*1.12601448551257)
[MeterBand_122]
Meter=Bar
MeasureName=Band122
MeterStyle=StyleAudiobar
TransformationMatrix=0.34801579;-0.93748867;0.93748867;0.34801579;(#CRadius#*1.37499546850816);(#Cradius#*1.13920631666109)
[MeterBand_123]
Meter=Bar
MeasureName=Band123
MeterStyle=StyleAudiobar
TransformationMatrix=0.38057009;-0.92475208;0.92475208;0.38057009;(#CRadius#*1.36990083087717);(#Cradius#*1.15222803722174)
[MeterBand_124]
Meter=Bar
MeasureName=Band124
MeterStyle=StyleAudiobar
TransformationMatrix=0.41265934;-0.91088543;0.91088543;0.41265934;(#CRadius#*1.36435417318485);(#Cradius#*1.16506373460813)
[MeterBand_125]
Meter=Bar
MeasureName=Band125
MeterStyle=StyleAudiobar
TransformationMatrix=0.44424431;-0.89590568;0.89590568;0.44424431;(#CRadius#*1.3583622734656);(#Cradius#*1.17769772355482)
[MeterBand_126]
Meter=Bar
MeasureName=Band126
MeterStyle=StyleAudiobar
TransformationMatrix=0.47528641;-0.87983113;0.87983113;0.47528641;(#CRadius#*1.35193245384105);(#Cradius#*1.19011456528477)
[MeterBand_127]
Meter=Bar
MeasureName=Band127
MeterStyle=StyleAudiobar
TransformationMatrix=0.50574772;-0.86268143;0.86268143;0.50574772;(#CRadius#*1.34507257157245);(#Cradius#*1.20229908637554)
[MeterBand_128]
Meter=Bar
MeasureName=Band128
MeterStyle=StyleAudiobar
TransformationMatrix=0.53559099;-0.84447752;0.84447752;0.53559099;(#CRadius#*1.33779100945902);(#Cradius#*1.21423639730134)
[MeterBand_129]
Meter=Bar
MeasureName=Band129
MeterStyle=StyleAudiobar
TransformationMatrix=0.56477978;-0.82524166;0.82524166;0.56477978;(#CRadius#*1.33009666559421);(#Cradius#*1.22591191062798)
[MeterBand_130]
Meter=Bar
MeasureName=Band130
MeterStyle=StyleAudiobar
TransformationMatrix=0.5932784;-0.80499736;0.80499736;0.5932784;(#CRadius#*1.32199894249213);(#Cradius#*1.23731135883887)
[MeterBand_131]
Meter=Bar
MeasureName=Band131
MeterStyle=StyleAudiobar
TransformationMatrix=0.62105203;-0.78376934;0.78376934;0.62105203;(#CRadius#*1.31350773559768);(#Cradius#*1.24842081176989)
[MeterBand_132]
Meter=Bar
MeasureName=Band132
MeterStyle=StyleAudiobar
TransformationMatrix=0.64806673;-0.76158355;0.76158355;0.64806673;(#CRadius#*1.30463342119431);(#Cradius#*1.25922669363214)
[MeterBand_133]
Meter=Bar
MeasureName=Band133
MeterStyle=StyleAudiobar
TransformationMatrix=0.6742895;-0.73846711;0.73846711;0.6742895;(#CRadius#*1.2953868437241);(#Cradius#*1.26971579960157)
[MeterBand_134]
Meter=Bar
MeasureName=Band134
MeterStyle=StyleAudiobar
TransformationMatrix=0.69968828;-0.71444826;0.71444826;0.69968828;(#CRadius#*1.28577930253586);(#Cradius#*1.27987531195537)


;---- Skin Functions ----

[ChangeCircleSize]
Meter=Shape
MeterStyle=Change-Circle-Size
UpdateDivider=-1


;---- Station list ----

[Stationlistbackground]
Meter=Shape
Shape=Rectangle 0,0,(#CRadius#*2),(#CRadius#*2),(#CRadius#*0.1) | Fill Color 0,0,0,200 | StrokeWidth (#CRadius#*0.004) | Stroke Color 255,255,255
Group=Stations
DynamicVariables=1
AntiAlias=1
Hidden=1
MouseLeaveAction=[!HideMeterGroup Stations]
UpdateDivider=-1

[Station1]
Meter=String
MeterStyle=CStations
Y=(#CRadius#*0.05)	
Text=#StationTitle1#
LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle1#"][!WriteKeyValue Variables "WRASImage" "#StationImage1#"][!WriteKeyValue Variables "WRASStream" "#StationURL1#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL1#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL1#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption Station1 FontColor #Circle-RoundlineFillColor1#]
MouseLeaveAction=[!SetOption Station1 FontColor 210,210,210,255]

[Station2]
Meter=String
MeterStyle=CStations
Y=(#CRadius#*0.28)	
Text=#StationTitle2#
LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle2#"][!WriteKeyValue Variables "WRASImage" "#StationImage2#"][!WriteKeyValue Variables "WRASStream" "#StationURL2#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL2#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL2#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Circle-RoundlineFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

[Station3]
Meter=String
MeterStyle=CStations
Y=(#CRadius#*0.51)	
Text=#StationTitle3#
LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle3#"][!WriteKeyValue Variables "WRASImage" "#StationImage3#"][!WriteKeyValue Variables "WRASStream" "#StationURL3#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL3#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL3#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Circle-RoundlineFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

[Station4]
Meter=String
MeterStyle=CStations
Y=(#CRadius#*0.74)	
Text=#StationTitle4#
LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle4#"][!WriteKeyValue Variables "WRASImage" "#StationImage4#"][!WriteKeyValue Variables "WRASStream" "#StationURL4#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL4#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL4#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Circle-RoundlineFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

[Station5]
Meter=String
MeterStyle=CStations
Y=(#CRadius#*0.97)	
Text=#StationTitle5#
LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle5#"][!WriteKeyValue Variables "WRASImage" "#StationImage5#"][!WriteKeyValue Variables "WRASStream" "#StationURL5#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL5#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL5#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Circle-RoundlineFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

[Station6]
Meter=String
MeterStyle=CStations
Y=(#CRadius#*1.20)	
Text=#StationTitle6#
LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle6#"][!WriteKeyValue Variables "WRASImage" "#StationImage6#"][!WriteKeyValue Variables "WRASStream" "#StationURL6#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL6#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL6#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Circle-RoundlineFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

[Station7]
Meter=String
MeterStyle=CStations
Y=(#CRadius#*1.43)	
Text=#StationTitle7#
LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle7#"][!WriteKeyValue Variables "WRASImage" "#StationImage7#"][!WriteKeyValue Variables "WRASStream" "#StationURL7#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL7#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL7#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Circle-RoundlineFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

[Station8]
Meter=String
MeterStyle=CStations
Y=(#CRadius#*1.66)	
Text=#StationTitle8#
LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle8#"][!WriteKeyValue Variables "WRASImage" "#StationImage8#"][!WriteKeyValue Variables "WRASStream" "#StationURL8#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL8#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL8#"][!HideMeterGroup RadioOff][!ShowMeterGroup Radio][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Circle-RoundlineFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor 210,210,210,255]

