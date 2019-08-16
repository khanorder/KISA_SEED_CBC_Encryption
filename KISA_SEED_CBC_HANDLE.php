<?php
require_once ('KISA_SEED_CBC.php');

class KISA_SEED_CBC_HANDLE
{
	private static $g_bszUser_key = [ "f1", "96", "ff", "18", "28", "c8", "ef", "cc", "ab", "1a", "fd", "8d", "8c", "b9", "a4", "34" ];
	private static $g_bszIV = [ "78", "69", "81", "ab", "4a", "4c", "2c", "a8", "a9", "99", "67", "81", "77", "a1", "cc", "bb" ];
	private static $SeedBlockSize = 16;
	private static $PADDING_VALUE = 0x0F;

	public function addPadding($source, $blockSize) {
		$paddingResult = $source;
		$paddingCount = $blockSize - (count($source) % $blockSize);
		if (!$paddingCount) {
			for($i=0;$i<self::$SeedBlockSize;$i++) {
				$paddingResult[] = self::$PADDING_VALUE;
			}
		} else {
			for($i=0;$i<$paddingCount;$i++) {
				$paddingResult[] = 0x0A;
			}
		}

		return $paddingResult;
	}

	public function removePadding($source, $blockSize) {
		$paddingResult = $source;
		$byte_length = count($source);
		$lb_start = $byte_length - $blockSize - 1;
		$is_padding = false;
		$padding_start = 0;
		for ($i = $lb_start; $i < $byte_length; $i++) { 
			if ($source[$i] == 10) {
				$is_padding = true;
				$padding_start = $i;
				break;
			}
		}
		for ($i = $padding_start; $i < $byte_length; $i++) {
			array_pop($paddingResult);
		}

		return $paddingResult;
	}

	public function encrypt($str) {

		$planBytes = array_slice(unpack('c*', $str), 0);
		$planBytes = $this->addPadding($planBytes, self::$SeedBlockSize);
		$keyBytes = self::$g_bszUser_key;
		$IVBytes = self::$g_bszIV;
		
		for($i = 0; $i < 16; $i++)
		{
			$keyBytes[$i] = hexdec($keyBytes[$i]);
			$IVBytes[$i] = hexdec($IVBytes[$i]);
		}

		if (count($planBytes) == 0) {
			return $str;
		}
		$ret = null;
		$bszChiperText = null;
		$pdwRoundKey = array_pad(array(),32,0);

		$bszChiperText = KISA_SEED_CBC::SEED_CBC_Encrypt($keyBytes, $IVBytes, $planBytes, 0, count($planBytes));

		$r = count($bszChiperText);

		for($i=0;$i< $r;$i++) {
			$ret.= ($ret ? "," : "") . sprintf("%02X", $bszChiperText[$i]);
		}
		return $ret;
	}

	public function decrypt($str) {
		$planBytes = [];
		$keyBytes = self::$g_bszUser_key;
		$IVBytes = self::$g_bszIV;
		
		for($i = 0; $i < 16; $i++)
		{
			$keyBytes[$i] = hexdec($keyBytes[$i]);
			$IVBytes[$i] = hexdec($IVBytes[$i]);
		}

		$hex_arr = explode(",", $str);

		foreach ($hex_arr as $hex) {
			$dec = hexdec($hex);
			$planBytes[] = $dec;
		}

		if (count($planBytes) == 0) {
			return $str;
		}

		$pdwRoundKey = array_pad(array(),32,0);

		$bszPlainText = null;

		$planBytresMessage = "";
		$bszPlainText = KISA_SEED_CBC::SEED_CBC_Decrypt($keyBytes, $IVBytes, $planBytes, 0, count($planBytes));
		for($i=0;$i< sizeof($bszPlainText);$i++) {
			$planBytresMessage .=  sprintf("%02X", hexdec($bszPlainText[$i])).",";
		}

		$decryptHexStr = substr($planBytresMessage,0,strlen($planBytresMessage)-1);
		$decryptHex = explode(",", $decryptHexStr);

		$dec_data = call_user_func_array("pack", array_merge(array("c*"), $decryptHex));
		return $dec_data ? trim($dec_data) : "";
	}

}