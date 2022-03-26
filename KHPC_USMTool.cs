using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;

public enum AudioType{
	HCA,
	ADX,
	UNK
}

class Test{
	static void parseUSM(string f){
		Console.WriteLine("Analyzing: " + f);
		byte[] bytes = File.ReadAllBytes(f);
		
		using(MemoryStream output = new MemoryStream())
		using(MemoryStream ms = new MemoryStream(bytes))
		using(BinaryReader br = new BinaryReader(ms)){
			byte[] magic = br.ReadBytes(4);
			string signature = System.Text.Encoding.ASCII.GetString(magic);
			
			if(signature != "CRID"){ //CRID
				Console.WriteLine(signature + " not a USM/CRID signature");
				return;
			}else{
				Console.WriteLine("Valid USM/CRID file");
			}
			Console.WriteLine("Drag the HCA file you would like to inject: ");
			string input = Console.ReadLine();
			bool validInput = true;
			if(!File.Exists(input)){
				Console.WriteLine("Could not find file: " + input);
				validInput = false;
			}
						
			int count = 0;
			long totalLength = 0;
			
			byte[] hca = validInput ? File.ReadAllBytes(input) : new byte[1024];
			using(MemoryStream hcam = new MemoryStream(hca))
			using(BinaryReader hcar = new BinaryReader(hcam)){
				List<byte> magicList = hcar.ReadBytes(2).ToList();
				magicList.Add(0x00);
				magicList.Add(0x00);
				byte[] inputMagic = magicList.ToArray();
				Array.Reverse(inputMagic);
				AudioType audioType = validInput ? AudioType.UNK : AudioType.ADX;
				if(validInput){
					switch((uint)BitConverter.ToInt32(inputMagic, 0)){
						case (uint)0x48430000: //HCA
							audioType = AudioType.HCA;
							break;
						case (uint)0x80000000: //ADX
							audioType = AudioType.ADX;
							break;
					}
				}
				
				Console.WriteLine("AudioType detected: " + audioType.ToString());
				
				switch(audioType){
					case AudioType.HCA:
						hcam.Seek(0x60, SeekOrigin.Begin);
						break;
					case AudioType.ADX:
						byte[] copyrightBytes = hcar.ReadBytes(2);
						Array.Reverse(copyrightBytes);
						hcam.Seek(BitConverter.ToInt16(copyrightBytes, 0), SeekOrigin.Current);
						Console.WriteLine(hcam.Position + " - " + BitConverter.ToInt16(copyrightBytes, 0));
						break;
				}
				
				int skipSFA = 0;
				while(br.BaseStream.Position != bytes.Length){
					long offset = br.BaseStream.Position;
					if(offset > 4){
						magic = br.ReadBytes(4);
						signature = System.Text.Encoding.ASCII.GetString(magic);
					}
					
					if(audioType == AudioType.HCA){
						output.Write(magic, 0, 4);
						
						byte[] byteArray = br.ReadBytes(4);
						output.Write(byteArray, 0, 4);
						
						Array.Reverse(byteArray);
						int length = BitConverter.ToInt32(byteArray, 0);
						
						if(signature == "@SFA" && (length == 0xc18 || length == 0x418)){
							Console.WriteLine(signature + " HCA (" + length + ") at: " + offset);
							totalLength += length - 0x18;
							count++;
							
							output.Write(br.ReadBytes(0x18), 0, 0x18);
							byte[] inputBytes = validInput ? hcar.ReadBytes(length - 0x18) : br.ReadBytes(length - 0x18);
							output.Write(inputBytes, 0, length - 0x18);
							if(validInput) ms.Seek(length - 0x18, SeekOrigin.Current);
						}else{
							output.Write(br.ReadBytes(length), 0, length);
						}
					}
					
					if(audioType == AudioType.ADX){						
						if(validInput) output.Write(magic, 0, 4);
						
						byte[] byteArray = br.ReadBytes(4);
						if(validInput) output.Write(byteArray, 0, 4);
						
						Array.Reverse(byteArray);
						int length = BitConverter.ToInt32(byteArray, 0);
						
						byteArray = br.ReadBytes(2);
						if(validInput) output.Write(byteArray, 0, 2);
						Array.Reverse(byteArray);
						int header = BitConverter.ToInt16(byteArray, 0);
						
						byteArray = br.ReadBytes(2);
						if(validInput) output.Write(byteArray, 0, 2);
						Array.Reverse(byteArray);
						int skip = BitConverter.ToInt16(byteArray, 0);
						
						if(signature == "@SFA") skipSFA++;
						if(skipSFA > 3 && signature == "@SFA" && (length == 0x1538 || length == 0x15b8 || length == 0x1398 || length == 0x0138 || (length == 0x0038 && skip > 0))){
							Console.WriteLine(signature + " ADX (" + length + ") at: " + offset);
							totalLength += length - header;
							count++;
							
							byte[] headerBytes = br.ReadBytes(header - 0x04);
							if(validInput) output.Write(headerBytes, 0, headerBytes.Length);
							
							byte[] data = validInput ? hcar.ReadBytes(length - header - skip) : br.ReadBytes(length - header - skip);
							if(validInput) br.ReadBytes(length - header - skip);
							if(length == 0x1538 || length == 0x15b8 || length == 0x1398) data = DecryptADX(data);
							
							output.Write(data, 0, data.Length);
							
							byte[] skipData = br.ReadBytes(skip);
							if(validInput) output.Write(skipData, 0, skipData.Length);
						}else{
							byte[] nonSFAbytes = br.ReadBytes(length - 0x04);
							if(validInput) output.Write(nonSFAbytes, 0, nonSFAbytes.Length);				
						}
					}
				}
			}
			Console.WriteLine("Found SFA count: " + count);
			Console.WriteLine("Total audio length: " + totalLength);
			Console.WriteLine("Output: " + output.Length);
			
			string outputFile = Path.Combine(Path.GetDirectoryName(f), Path.GetFileNameWithoutExtension(f)) + "_edited" + Path.GetExtension(f);
			File.WriteAllBytes(outputFile, output.ToArray());
		}
	}
	
	static byte[] DecryptADX(byte[] encrypted){
		byte[] key = new byte[32]{0xb0, 0x55, 0x26, 0x52, 0xd2, 0x55, 0x04, 0x43, 0x91, 0x55, 0xd9, 0x52, 0xb0, 0x55, 0x17, 0x43, 
                                  0x4d, 0x55, 0xbc, 0x52, 0x04, 0x55, 0xf7, 0x43, 0xe1, 0x55, 0x8f, 0x52, 0x30, 0x55, 0x86, 0x43};
		
		if(encrypted.Length >= 0x140){		
			for(int i=0x140;i<encrypted.Length;i++){
				encrypted[i] = (byte)(encrypted[i] ^ key[i%key.Length]);
			}
		}
		
		return encrypted;
	}
	
	static void Main(string[] args){
		System.Reflection.Assembly assembly = System.Reflection.Assembly.GetExecutingAssembly();
		System.Diagnostics.FileVersionInfo fvi = System.Diagnostics.FileVersionInfo.GetVersionInfo(assembly.Location);
		string version = fvi.FileVersion;
		
		Console.WriteLine("KHPC_USMTool - v" + version); 

		for(int i=0;i<args.Length;i++){
			if(File.Exists(args[i])) parseUSM(args[i]);
		}
		Console.WriteLine("Done!");
		Console.ReadLine();
	}
}