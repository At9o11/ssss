ssss
====

ss

1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
76
77
78
79
80
81
82
83
84
85
86
87
88
89
90
91
92
93
94
95
96
97
98
99
100
101
102
103
104
105
106
107
108
109
110
111
112
113
114
115
116
117
118
119
120
121
122
123
124
125
126
127
128
129
130
131
132
package burp;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeSet;
import java.io.PrintWriter;
 
 
 
public class BurpExtender implements IBurpExtender, IIntruderPayloadGeneratorFactory, IHttpListener
{
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    
    //
    // implement IBurpExtender
    //
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName("Signature Forge");
        
        // register ourselves as an Intruder payload generator
        callbacks.registerIntruderPayloadGeneratorFactory(this);
        
        // register ourselves as an HttpListener
        callbacks.registerHttpListener(this);
        
        stdout = new PrintWriter(callbacks.getStdout(), true);
        
    }
 
    //
    // implement IIntruderPayloadGeneratorFactory
    //
    
    @Override
    public String getGeneratorName()
    {
        return "Current EPOCH";
    }
 
    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack)
    {
        // return a new IIntruderPayloadGenerator to generate payloads for this attack
        return new IntruderPayloadGenerator();
    }
    
   
    // IHttpListener
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {
        
        byte[] request_byte = messageInfo.getRequest();
        IParameter sig_param = helpers.getRequestParameter(request_byte, "signature");
        
        if (toolFlag == 32 && messageIsRequest && !sig_param.equals(null))
        {
            String param1 = helpers.getRequestParameter(request_byte, "param1").getValue();
            String param2 = helpers.getRequestParameter(request_byte, "param2").getValue();
            String param3 = helpers.getRequestParameter(request_byte, "param3").getValue();
            
            String sig_string = calcsig(param1, param2, param3);
           
            
            sig_param = helpers.buildParameter(sig_param.getName(), sig_string, sig_param.getType());
            
            request_byte = helpers.updateParameter(request_byte, sig_param);
            messageInfo.setRequest(request_byte);
        }
 
    }
 
    
    //
    //  This is the signature generation function that needs to be custom to each environment
    //
    public static String calcsig(String param1, String param2, String param3)
    {
        HashMap localHashMap = new HashMap();
        localHashMap.put(param1);
        localHashMap.put(param2);
        localHashMap.put(param3);
        return localHashMap;
    }
    
    
    
    //
    // class to generate payloads from a simple list
    //
    
    class IntruderPayloadGenerator implements IIntruderPayloadGenerator
    {
        int payloadIndex ;
        
        @Override
        public boolean hasMorePayloads()
        {
            return true;
        }
        
        
        @Override
        public byte[] getNextPayload(byte[] baseValue)
        {
            
            String time = String.valueOf(System.currentTimeMillis()/1000);
            byte[] payload = time.getBytes();
            
            return payload;
        }
        
        
 
        @Override
        public void reset()
        {
            payloadIndex = 0;
        }
    }
    
}
