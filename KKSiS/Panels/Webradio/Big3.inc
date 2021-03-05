[Variables]

;---- Style ----
@Include5=#@#Include\PanelStyleBig.inc


---- Measures Volume ----

[VolumeWin]
Measure			=Plugin
Plugin			=Win7AudioPlugin
UpdateDivider	=1

[VolumeWinPercent]
Measure			=Calc
Formula			=VolumeWin
UpdateDivider	=1
IfCondition		=(VolumeWinPercent = -1) && (#WRActive# = 1)
IfTrueAction	=[!ShowMeter "ButtonMute"][!HideMeter "ButtonVol"]
IfFalseAction	=[!HideMeter "ButtonMute"][!HideMeter "ButtonVol"]
IfCondition2	=(VolumeWinPercent > 0) && (#WRActive# = 1)
IfTrueAction2	=[!HideMeter "ButtonMute"][!ShowMeter "ButtonVol"]
DynamicVariables=1

[VolumeWinSmooth]
Measure=Calc
Formula=100-VolumeWin
MaxValue=100
MinValue=0
AverageSize=6
UpdateDivider=1

[FunctionSwitch]
Measure			=Calc
Formula			=#WRHideVolume#+#WRShowColoredBtnFrame#
IfCondition		=(#WRHideVolume# = 0) && (#WRActive# = 1)
IfTrueAction	=[!ShowMeter "Volume"]
IfFalseAction	=[!HideMeter "Volume"]
IfCondition2	=(#WRShowColoredBtnFrame# = 1)
IfTrueAction2	=[!SetVariable CurrentBarColor #Panel-BarFillColor3#]
DynamicVariables=1
Updatedivider	=1


;---- Measures Audiolevel ----

[WinAudioLevel]
	Measure=Plugin
	Plugin=AudioLevel
	Port=Output
	FFTSize=1024
	FFTAttack=15
	FFTDecay=200
	Bands=33
	UpdateDivier=1
[Band0]
	Measure=Plugin
	Plugin=AudioLevel
	Parent=WinAudioLevel
	Type=Band
	BandIdx=0
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


;---- Default Cover & Station ----

[SpeakerLogo]
	Meter=Image
	ImageName=#@#Images\General\Speaker.png
	X=(#PHeight#*0.15)
	Y=(#PHeight#*0.1)
	W=(#PHeight#*0.8)
	H=(#PHeight#*0.8)
	Hidden=#WRActive#
	Group=RadioOff
	DynamicVariables=1
	Updatedivider=-1

[Title]
	Meter=String
	MeterStyle=PText | PTitle
	Text=Webradio
	Group=RadioOff
	Hidden=#WRActive#
	DynamicVariables=1
	Updatedivider=-1


;---- Skin Functions ----

[KlickFunctions]
Meter=Shape
MeterStyle=KlickFunctionsBG
MouseScrollDownAction=[!CommandMeasure "VolumeWin" "ChangeVolume -3"]
MouseScrollUpAction=[!CommandMeasure "VolumeWin" "ChangeVolume +3"]


;---- Active Cover & Station ----

[Cover]
	Meter=Image
	ImageName=#@#Images\Stations\#WRASImage#
	AntiAlias=1
	X=(#PHeight#*0.29)
	Y=(#PHeight#*0.07)
	W=(#PHeight#*0.70)
	H=(#PHeight#*0.70)
	Hidden=#WRInactive#
	Group=Radio
	LeftMouseUpAction=[#WRASTracklist#]
	DynamicVariables=1
	UpdateDivider=10

[Volume]
	Meter=String
	MeterStyle=PText | PSize8
	StringAlign=Center
	MeasureName=VolumeWinPercent
	X=(#PHeight#*0.16)
	Y=(#PHeight#*0.08)
	Group=Radio
	Hidden=#WRInactive#
	Text=Vol#CRLF#%1
	UpdateDivider=3


;---- Audiolevelmeter ----

[StyleAudioBar]
	Flip=0
	BarColor=#CurrentBarColor#
	SolidColor=#Panel-BGShadowColor#,20
	BarOrientation=Vertical
	Y=(#PHeight#*0.8)
	W=(#PHeight#*0.02)
	H=(#PHeight#*0.2)
	Group=Radio
	AntiAlias=1
	DynamicVariables=1
	Hidden=#WRInactive#
	UpdateDivider=1

[MeterBand0]
	Meter=Bar
	MeterStyle=StyleAudiobar
	MeasureName=Band0
	X=(#PHeight#*0.05)
[MeterBand1]
	Meter=Bar
	MeasureName=Band1
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.08)
[MeterBand2]
	Meter=Bar
	MeasureName=Band2
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.11)
[MeterBand3]
	Meter=Bar
	MeasureName=Band3
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.14)
[MeterBand4]
	Meter=Bar
	MeasureName=Band4
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.17)
[MeterBand5]
	Meter=Bar
	MeasureName=Band5
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.20)
[MeterBand6]
	Meter=Bar
	MeasureName=Band6
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.23)
[MeterBand7]
	Meter=Bar
	MeasureName=Band7
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.26)
[MeterBand8]
	Meter=Bar
	MeasureName=Band8
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.29)
[MeterBand9]
	Meter=Bar
	MeasureName=Band9
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.32)
[MeterBand10]
	Meter=Bar
	MeasureName=Band10
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.35)
[MeterBand11]
	Meter=Bar
	MeasureName=Band11
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.38)
[MeterBand12]
	Meter=Bar
	MeasureName=Band12
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.41)
[MeterBand13]
	Meter=Bar
	MeasureName=Band13
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.44)
[MeterBand14]
	Meter=Bar
	MeasureName=Band14
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.47)
[MeterBand15]
	Meter=Bar
	MeasureName=Band15
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.50)
[MeterBand16]
	Meter=Bar
	MeasureName=Band16
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.53)
[MeterBand17]
	Meter=Bar
	MeasureName=Band17
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.56)
[MeterBand18]
	Meter=Bar
	MeasureName=Band18
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.59)
[MeterBand19]
	Meter=Bar
	MeasureName=Band19
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.62)
[MeterBand20]
	Meter=Bar
	MeasureName=Band20
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.65)
[MeterBand21]
	Meter=Bar
	MeasureName=Band21
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.68)
[MeterBand22]
	Meter=Bar
	MeasureName=Band22
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.71)
[MeterBand23]
	Meter=Bar
	MeasureName=Band23
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.74)
[MeterBand24]
	Meter=Bar
	MeasureName=Band24
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.77)
[MeterBand25]
	Meter=Bar
	MeasureName=Band25
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.80)
[MeterBand26]
	Meter=Bar
	MeasureName=Band26
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.83)
[MeterBand27]
	Meter=Bar
	MeasureName=Band27
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.86)
[MeterBand28]
	Meter=Bar
	MeasureName=Band28
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.89)
[MeterBand29]
	Meter=Bar
	MeasureName=Band29
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.92)
[MeterBand30]
	Meter=Bar
	MeasureName=Band30
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.95)
[MeterBand31]
	Meter=Bar
	MeasureName=Band31
	MeterStyle=StyleAudiobar
	X=(#PHeight#*0.98)
[MeterBand32]
	Meter=Bar
	MeasureName=Band32
	MeterStyle=StyleAudiobar
	X=(#PHeight#*1.01)


;---- Buttons ----

[ButtonFrameColored]
	Meter=Shape
	Shape=Rectangle (#PHeight#*0.11),(#PHeight#*0.30),(#PHeight#*0.1),(#PHeight#*0.1),(#PHeight#*0.01) | StrokeWidth (#PHeight#*0.01) | Stroke LinearGradient ButtonFrameColor#WRShowColoredBtnFrame##Panel-BarFillStyle# | Fill Color 0,0,0,0
	Shape2=Rectangle (#PHeight#*0.11),(#PHeight#*0.45),(#PHeight#*0.1),(#PHeight#*0.1),(#PHeight#*0.01) | StrokeWidth (#PHeight#*0.01) | Stroke LinearGradient ButtonFrameColor#WRShowColoredBtnFrame##Panel-BarFillStyle# | Fill Color 0,0,0,0
	Shape3=Rectangle (#PHeight#*0.11),(#PHeight#*0.60),(#PHeight#*0.1),(#PHeight#*0.1),(#PHeight#*0.01) | StrokeWidth (#PHeight#*0.01) | Stroke LinearGradient ButtonFrameColor#WRShowColoredBtnFrame##Panel-BarFillStyle# | Fill Color 0,0,0,0
	ButtonFrameColor01=90 | #Panel-ButtonColor# ; 0.0 | #Panel-ButtonColor# ; 1.0
	ButtonFrameColor02=90 | #Panel-ButtonColor# ; 0.0 | #Panel-ButtonColor# ; 1.0
	ButtonFrameColor03=90 | #Panel-ButtonColor# ; 0.0 | #Panel-ButtonColor# ; 1.0
	ButtonFrameColor11=90 | #Panel-BarFillColor1# ; 0.0 | #Panel-BarFillColor1# ; 1.0
	ButtonFrameColor12=90 | #Panel-BarFillColor3# ; 0.0 |  #Panel-BarFillColor1# ; 1.0
	ButtonFrameColor13=90 | #Panel-BarFillColor3# ; 0.0 | #Panel-BarFillColor2# ; 0.5 | #Panel-BarFillColor1# ; 1.0
	DynamicVariables=1
	AntiAlias=1
	Hidden=#WRInactive#
	Group=Radio
	UpdateDivider=10

[ButtonVol]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnVol.png
	ImageTint=#Panel-ButtonColor#
	X=(#PHeight#*0.13)	
	Y=(#PHeight#*0.32)	
	H=(#PHeight#*0.06)	
	W=(#PHeight#*0.06)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonVol ImageTint #Panel-BarFillColor1#]
	MouseLeaveAction=[!SetOption ButtonVol ImageTint #Panel-ButtonColor#]
	LeftMouseUpAction=[!CommandMeasure "VolumeWin" "ToggleMute"]
	UpdateDivider=1

[ButtonMute]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnVolMute.png
	ImageTint=#Panel-ButtonColor#
	X=(#PHeight#*0.13)	
	Y=(#PHeight#*0.32)	
	H=(#PHeight#*0.06)	
	W=(#PHeight#*0.06)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonMute ImageTint #Panel-BarFillColor1#]
	MouseLeaveAction=[!SetOption ButtonMute ImageTint #Panel-ButtonColor#]
	LeftMouseUpAction=[!CommandMeasure "VolumeWin" "ToggleMute"]
	UpdateDivider=1

[ButtonStop]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnStop.png
	ImageTint=#Panel-ButtonColor#
	X=(#PHeight#*0.13)	
	Y=(#PHeight#*0.47)	
	H=(#PHeight#*0.06)	
	W=(#PHeight#*0.06)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonStop ImageTint #Panel-BarFillColor1#]
	MouseLeaveAction=[!SetOption ButtonStop ImageTint #Panel-ButtonColor#]
	LeftMouseUpAction=[!WriteKeyValue Variables "WRActive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "1" "#@#Variables.inc"]["#@#Tools\omnimoapp.exe" Radio Kill][!HideMeterGroup Radio][!ShowMeterGroup RadioOff][!Redraw]
	UpdateDivider=1

[ButtonPlay]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnPlay.png
	ImageTint=#Panel-ButtonColor#
	X=(#PHeight#*0.13)		
	Y=(#PHeight#*0.62)	
	H=(#PHeight#*0.06)	
	W=(#PHeight#*0.06)	
	Hidden=1
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonPlay ImageTint #Panel-BarFillColor1#]
	MouseLeaveAction=[!SetOption ButtonPlay ImageTint #Panel-ButtonColor#]
	LeftMouseUpAction=["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#WRASStream#"][!HideMeter ButtonPlay][!ShowMeter ButtonPause]
	UpdateDivider=1

[ButtonPause]
	Meter=Image
	ImageName=#@#Images\Buttons\BtnPause.png
	ImageTint=#Panel-ButtonColor#
	X=(#PHeight#*0.13)		
	Y=(#PHeight#*0.62)	
	H=(#PHeight#*0.06)	
	W=(#PHeight#*0.06)	
	Hidden=#WRInactive#
	DynamicVariables=1
	Group=Radio
	MouseOverAction=[!SetOption ButtonPause ImageTint #Panel-BarFillColor1#]
	MouseLeaveAction=[!SetOption ButtonPause ImageTint #Panel-ButtonColor#]
	LeftMouseUpAction=["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" Off][!HideMeter ButtonPause][!ShowMeter ButtonPlay]
	UpdateDivider=1


;---- Bar ----

[Bar1]
	Meter=Shape
	MeterStyle=BarStyle-VRx1
	UpdateDivider=10

[Bar1Measure]
	Meter=Bar
	MeterStyle=BarStyle-VRx1Measure
	MeasureName=VolumeWinSmooth
	UpdateDivider=1

[Bar1Stroke]
	Meter=Shape
	MeterStyle=BarStyle-VRx1Stroke
	UpdateDivider=10


;---- Skin Functions ----

[ChangePanelSize]
Meter=Shape
MeterStyle=Change-Panel-Size


;---- Station list ----

[ShowStationMarker]
Meter=Image
ImageName=#@#Images\Buttons\Marker.png
ImageTint=#Panel-ButtonColor#
X=(#PHeight#*1.04)	
Y=(-#PHeight#*0.04+#PHeight#*0.12*#Stationmarker#)
H=(#PHeight#*0.06)	
W=(#PHeight#*0.06)
Hidden=#WRInactive#
DynamicVariables=1
Group=Radio

[Station1]
Meter=String
MeterStyle=PStationsBigPanel
Y=(#PHeight#*0.03)	
Text=#StationTitle1#
LeftMouseUpAction=[!WriteKeyValue Variables Stationmarker "1"][!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle1#"][!WriteKeyValue Variables "WRASImage" "#StationImage1#"][!WriteKeyValue Variables "WRASStream" "#StationURL1#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL1#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL1#"][!Refresh]
MouseOverAction=[!SetOption Station1 FontColor #Panel-BarFillColor1#]
MouseLeaveAction=[!SetOption Station1 FontColor #Panel-FontColor#]

[Station2]
Meter=String
MeterStyle=PStationsBigPanel
Y=(#PHeight#*0.15)	
Text=#StationTitle2#
LeftMouseUpAction=[!WriteKeyValue Variables Stationmarker "2"][!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle2#"][!WriteKeyValue Variables "WRASImage" "#StationImage2#"][!WriteKeyValue Variables "WRASStream" "#StationURL2#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL2#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL2#"][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Panel-BarFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor #Panel-FontColor#]

[Station3]
Meter=String
MeterStyle=PStationsBigPanel
Y=(#PHeight#*0.27)
Text=#StationTitle3#
LeftMouseUpAction=[!WriteKeyValue Variables Stationmarker "3"][!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle3#"][!WriteKeyValue Variables "WRASImage" "#StationImage3#"][!WriteKeyValue Variables "WRASStream" "#StationURL3#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL3#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL3#"][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Panel-BarFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor #Panel-FontColor#]

[Station4]
Meter=String
MeterStyle=PStationsBigPanel
Y=(#PHeight#*0.39)
Text=#StationTitle4#
LeftMouseUpAction=[!WriteKeyValue Variables Stationmarker "4"][!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle4#"][!WriteKeyValue Variables "WRASImage" "#StationImage4#"][!WriteKeyValue Variables "WRASStream" "#StationURL4#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL4#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL4#"][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Panel-BarFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor #Panel-FontColor#]

[Station5]
Meter=String
MeterStyle=PStationsBigPanel
Y=(#PHeight#*0.51)
Text=#StationTitle5#
LeftMouseUpAction=[!WriteKeyValue Variables Stationmarker "5"][!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle5#"][!WriteKeyValue Variables "WRASImage" "#StationImage5#"][!WriteKeyValue Variables "WRASStream" "#StationURL5#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL5#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL5#"][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Panel-BarFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor #Panel-FontColor#]

[Station6]
Meter=String
MeterStyle=PStationsBigPanel
Y=(#PHeight#*0.63)
Text=#StationTitle6#
LeftMouseUpAction=[!WriteKeyValue Variables Stationmarker "6"][!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle6#"][!WriteKeyValue Variables "WRASImage" "#StationImage6#"][!WriteKeyValue Variables "WRASStream" "#StationURL6#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL6#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL6#"][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Panel-BarFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor #Panel-FontColor#]

[Station7]
Meter=String
MeterStyle=PStationsBigPanel
Y=(#PHeight#*0.75)
Text=#StationTitle7#
LeftMouseUpAction=[!WriteKeyValue Variables Stationmarker "7"][!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle7#"][!WriteKeyValue Variables "WRASImage" "#StationImage7#"][!WriteKeyValue Variables "WRASStream" "#StationURL7#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL7#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL7#"][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Panel-BarFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor #Panel-FontColor#]

[Station8]
Meter=String
MeterStyle=PStationsBigPanel
Y=(#PHeight#*0.87)
Text=#StationTitle8#
LeftMouseUpAction=[!WriteKeyValue Variables Stationmarker "8"][!WriteKeyValue Variables "WRActive" "1" "#@#Variables.inc"][!WriteKeyValue Variables "WRInactive" "0" "#@#Variables.inc"][!WriteKeyValue Variables "WRASTitle" "#StationTitle8#"][!WriteKeyValue Variables "WRASImage" "#StationImage8#"][!WriteKeyValue Variables "WRASStream" "#StationURL8#"][!WriteKeyValue Variables "WRASTracklist" "#StationTrackListURL8#"]["#@#Tools\omnimoapp.exe" Radio "#PathToVLC#" "#StationURL8#"][!Refresh]
MouseOverAction=[!SetOption #Currentsection# FontColor #Panel-BarFillColor1#]
MouseLeaveAction=[!SetOption #Currentsection# FontColor #Panel-FontColor#]
