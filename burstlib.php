<?php

    class Burstlib
    {
        public $nodeAddress;
        public $curve;
        public $convert;
        public function __construct($nodeAddr)
        {
            $this->nodeAddress = $nodeAddr;
            $this->curve = new Curve25519();
            $this->convert = new Converters();
        }

        public function signBytes($message, $secretPhrase)
        {
            $messageBytes = $message;
            $secretPhraseBytes = $this->convert->stringToByteArray($secretPhrase);
            $digest = $this->convert->hexStringToByteArray(hash("sha256", $secretPhrase));
            $s = $this->curve->keygen($digest)->s;
            $m = $this->convert->hexStringToByteArray(hash("sha256", hex2bin($this->convert->byteArrayToHexString($messageBytes))));
            $x = $this->convert->hexStringToByteArray(hash("sha256", hex2bin($this->convert->byteArrayToHexString(array_merge($m, $s)))));
            $key = $this->curve->keygen($x);
            $x = $key->k;
            $y = $key->p;
            $h = $this->convert->hexStringToByteArray(hash("sha256", hex2bin($this->convert->byteArrayToHexString(array_merge($m, $y)))));
            $v = $this->curve->sign($h, $x, $s);
            return (array_merge($v, $h));
        }

        public function verifyBytes($signature, $message, $publicKey)
        {
            $signatureBytes = ($signature);
            $messageBytes = $message;
            $publicKeyBytes = $this->convert->hexStringToByteArray($publicKey);
            $v = array_slice($signatureBytes, 0, 32);
            $h = array_slice($signatureBytes, 32);
            $y = $this->curve->verify($v, $h, $publicKeyBytes);
            $m = $this->convert->hexStringToByteArray(hash("sha256", hex2bin($this->convert->byteArrayToHexString($messageBytes))));
            $h2 =  $this->convert->hexStringToByteArray(hash("sha256", hex2bin($this->convert->byteArrayToHexString(array_merge($m, $y)))));
            return $this->convert->areByteArraysEqual($h, $h2);
        }

        public function generateToken($websiteString, $secretPhrase)
        {
            $epochNum = 1385294400;
            $hexwebsite = $this->convert->stringToHexString($websiteString);
            $website = $this->convert->hexStringToByteArray($hexwebsite);
            $data = array();
            $data = array_merge($website, $this->convert->hexStringToByteArray($this->convert->secretPhraseToPublicKey($secretPhrase)));
            $unix = time();
            $timestamp = $unix - $epochNum;
            $timestamparray = $this->convert->int32ToByteArray($timestamp);
            $data = array_merge($data, $timestamparray);
            $token = array();
            $token = array_merge($this->convert->hexStringToByteArray($this->convert->secretPhraseToPublicKey($secretPhrase)), $timestamparray);
            $sig = $this->signBytes($data, $secretPhrase);
            $token = array_merge($token, $sig);
            $buf = "";
            for ($ptr = 0; $ptr < 100; $ptr += 5) {
                $nbr = array();
                $nbr[0] = $token[$ptr] & 0xFF;
                $nbr[1] = $token[$ptr+1] & 0xFF;
                $nbr[2] = $token[$ptr+2] & 0xFF;
                $nbr[3] = $token[$ptr+3] & 0xFF;
                $nbr[4] = $token[$ptr+4] & 0xFF;
                $number = $this->convert->byteArrayToInteger($nbr);
                if ($number < 32) {
                    $buf.="0000000";
                } elseif ($number < 1024) {
                    $buf.="000000";
                } elseif ($number < 32768) {
                    $buf.="00000";
                } elseif ($number < 1048576) {
                    $buf.="0000";
                } elseif ($number < 33554432) {
                    $buf.="000";
                } elseif ($number < 1073741824) {
                    $buf.="00";
                } elseif ($number < 34359738368) {
                    $buf.="0";
                }
                $buf .= base_convert($number, 10, 32);
            }
            return $buf;
        }

        public function parseToken($tokenString, $website)
        {
            $websiteBytes = $this->convert->stringToByteArray($website);
            $tokenBytes = array();
            $i = 0;
            $j = 0;
            for (; $i < strlen($tokenString); $i += 8, $j += 5) {
                $number = intval(substr($tokenString, $i, 8), 32);
                $part = $this->convert->hexStringToByteArray(base_convert((String)$number, 10, 16));
                $tokenBytes[$j] = $part[4];
                $tokenBytes[$j + 1] = $part[3];
                $tokenBytes[$j + 2] = $part[2];
                $tokenBytes[$j + 3] = $part[1];
                $tokenBytes[$j + 4] = $part[0];
            }
            if ($i != 160) {
                new Exception("tokenString parsed to invalid size");
            }
            $publicKey = array();
            $publicKey = array_slice($tokenBytes, 0, 32);
            $timebytes = array($tokenBytes[32], $tokenBytes[33], $tokenBytes[34], $tokenBytes[35]);
            $timestamp = $this->convert->byteArrayToInteger($timebytes);
            $signature = array_slice($tokenBytes, 36, 100);
            $data = array_merge($websiteBytes, array_slice($tokenBytes, 0, 36));
            $isValid = $this->verifyBytes($signature, $data, $this->convert->byteArrayToHexString($publicKey));
            $ret = new STDClass();
            $ret->isValid = $isValid;
            $ret->timestamp = $timestamp;
            $ret->publicKey = $this->convert->byteArrayToHexString($publicKey);
            return $ret;
        }
    }
    class Converters
    {
        public function charToNibble($char)
        {
            switch ($char) {
                case "0": return 0;
                case "1": return 1;
                case "2": return 2;
                case "3": return 3;
                case "4": return 4;
                case "5": return 5;
                case "6": return 6;
                case "7": return 7;
                case "8": return 8;
                case "9": return 9;
                case "a": return 10;
                case "A": return 10;
                case "b": return 11;
                case "B": return 11;
                case "c": return 12;
                case "C": return 12;
                case "d": return 13;
                case "D": return 13;
                case "e": return 14;
                case "E": return 14;
                case "f": return 15;
                case "F": return 15;
            }
            return 0;
        }

        public function hexStringToByteArray($str)
        {
            $bytes = array();
            $i = 0;
            if (0 !== strlen($str) % 2) {
                array_push($bytes, $this->charToNibble($str[0]));
                ++$i;
            }
            for (; $i < strlen($str) - 1; $i += 2) {
                array_push($bytes, ($this->charToNibble($str[$i]) << 4) + $this->charToNibble($str[$i + 1]));
            }
            return $bytes;
        }

        public function byteArrayToHexString($bytes)
        {
            $nibbleToChar = ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"];
            $str = '';
            for ($i = 0; $i < count($bytes); ++$i) {
                if ($bytes[$i] < 0) {
                    $bytes[$i] += 256;
                }
                $str .= $nibbleToChar[$bytes[$i] >> 4] . $nibbleToChar[$bytes[$i] & 0x0F];
            }
            return $str;
        }

        public function stringToByteArray($str)
        {
            $bytes = array_pad(array(), strlen($str), 0);
            for ($i = 0; $i < strlen($str); ++$i) {
                $bytes[$i] = ord($str[$i]);
            }
            return $bytes;
        }

        public function areByteArraysEqual($bytes1, $bytes2)
        {
            if (count($bytes1) !== count($bytes2)) {
                return false;
            }
            for ($i = 0; $i < count($bytes1); ++$i) {
                if ($bytes1[$i] !== $bytes2[$i]) {
                    return false;
                }
            }
            return true;
        }

        public function secretPhraseToPublicKey($secretPhrase)
        {
            $secretPhraseBytes = $this->stringToByteArray($secretPhrase);
            $digest = $this->hexStringToByteArray(hash("sha256", $secretPhrase));
            return $this->byteArrayToHexString((new Curve25519())->keygen($digest)->p);
        }

        public function secretPhraseToPrivateKey($secretPhrase)
        {
            $h = $this->stringToByteArray(hash("sha256", $secretPhrase));
            return $this->byteArrayToHexString((new Curve25519())->clamp($h));
        }

        public function int32ToByteArray($long)
        {
            $byteArray = array_pad(array(), 4, 0);
            for ($index = 0; $index < count($byteArray); $index ++) {
                $byte = $long & 0xff;
                $byteArray [ $index ] = $byte;
                $long = ($long - $byte) / 256 ;
            }

            return $byteArray;
        }

        public function byteArrayToInteger($byteArray)
        {
            $intval = 0;
            for ($index = 0; $index < count($byteArray); $index ++) {
                $byt = $byteArray[$index] & 0xFF;
                $value = $byt * pow(256, $index);
                $intval += $value;
            }

            return $intval;
        }

        public function byteArrayToBigInteger($byteArray)
        {
            $intval = "0";
            for ($index = 0; $index < count($byteArray); $index ++) {
                $byt = $byteArray[$index] & 0xFF;
                $value = bcmul($byt, pow(256, $index));
                $intval = bcadd($intval, $value);
            }
            return $intval;
        }

        public function stringToHexString($str)
        {
            return $this->byteArrayToHexString($this->stringToByteArray($str));
        }

        public function getAccountIdFromPublicKey($publicKey)
        {
            $hex = $this->hexStringToByteArray($publicKey);
            $account = hash("sha256", hex2bin($this->byteArrayToHexString($hex)));
            $slice = array_slice($this->hexStringToByteArray($account), 0, 8);
            $accountId = $this->byteArrayToBigInteger($slice);
            return $accountId;
        }

        public function getAccountIdFromSecretPhrase($secretPhrase)
        {
            $publicKey = $this->secretPhraseToPublicKey($secretPhrase);
            $accountId = $this->getAccountIdFromPublicKey($publicKey);
            return $accountId;
        }
    }

class Curve25519
{
    public $KEY_SIZE = 32;
    public $UNPACKED_SIZE = 16;

    public $ORDER = [
                237, 211, 245, 92,
                26, 99, 18, 88,
                214, 156, 247, 162,
                222, 249, 222, 20,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 16
        ];

    public $ORDER_TIMES_8 = [
                104, 159, 174, 231,
                210, 24, 147, 192,
                178, 230, 188, 23,
                245, 206, 247, 166,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 128
        ];

    public $BASE_2Y = [
                22587, 610, 29883, 44076,
                15515, 9479, 25859, 56197,
                23910, 4462, 17831, 16322,
                62102, 36542, 52412, 16035
        ];

    public $BASE_R2Y = [
                5744, 16384, 61977, 54121,
                8776, 18501, 26522, 34893,
                23833, 5823, 55924, 58749,
                24147, 14085, 13606, 6080
        ];

    public $C1 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    public $C9 = [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    public $C486671 = [0x6D0F, 0x0007, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    public $C39420360 = [0x81C8, 0x0259, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    public $P25 = 33554431;
    public $P26 = 67108863;

    public function clamp(&$k)
    {
        $k[31] &= 0x7F;
        $k[31] |= 0x40;
        $k[ 0] &= 0xF8;
        return $k;
    }

    public function cpy32(&$d, &$s)
    {
        for ($i = 0; $i < 32; $i++) {
            $d[$i] = $s[$i];
        }
    }

    public function mula_small(&$p, &$q, $m, &$x, $n, $z)
    {
        $m = $m | 0;
        $n = $n | 0;
        $z = $z | 0;
        $v = 0;
        for ($i = 0; $i < $n; ++$i) {
            $v += ($q[$i + $m] & 0xFF) + $z * ($x[$i] & 0xFF);
            $p[$i + $m] = ($v & 0xFF);
            $v >>= 8;
        }
        return $v;
    }

    public function mula32(&$p, &$x, &$y, $t, $z)
    {
        $t = $t | 0;
        $z = $z | 0;
        $n = 31;
        $w = 0;
        $i = 0;
        for (; $i < $t; $i++) {
            $zy = $z * ($y[$i] & 0xFF);
            $w += $this->mula_small($p, $p, $i, $x, $n, $zy) + ($p[$i+$n] & 0xFF) + $zy * ($x[$n] & 0xFF);
            $p[$i + $n] = $w & 0xFF;
            $w >>= 8;
        }
        $p[$i + $n] = ($w + ($p[$i + $n] & 0xFF)) & 0xFF;
        return $w >> 8;
    }

    public function divmod(&$q, &$r, $n, &$d, $t)
    {
        $n = $n | 0;
        $t = $t | 0;
        $rn = 0;
        $dt = ($d[$t - 1] & 0xFF) << 8;
        if ($t > 1) {
            $dt |= ($d[$t - 2] & 0xFF);
        }
        while ($n-- >= $t) {
            $z = ($rn << 16) | (($r[$n] & 0xFF) << 8);
            if ($n > 0) {
                $z |= ($r[$n - 1] & 0xFF);
            }
            $i = $n - $t + 1;
            $z /= $dt;
            $rn += $this->mula_small($r, $r, $i, $d, $t, -$z);
            $q[$i] = ($z + $rn) & 0xFF;
            $this->mula_small($r, $r, $i, $d, $t, -$rn);
            $rn = $r[$n] & 0xFF;
            $r[$n] = 0;
        }

        $r[$t-1] = $rn & 0xFF;
    }

    public function numsize($x, $n)
    {
        while ($n-- !== 0 && $x[$n] === 0) {
        }
        return $n + 1;
    }

    public function egcd32(&$x, &$y, &$a, &$b)
    {
        $an;
        $bn = 32;
        $qn;
        $i;

        for ($i = 0; $i < 32; $i++) {
            $x[$i] = $y[$i] = 0;
        }
        $x[0] = 1;
        $an = $this->numsize($a, 32);

        if ($an === 0) {
            return $y;
        } /* division by zero */
        $temp = array_pad(array(), 64, 0);
        while (true) {
            $qn = $bn - $an + 1;
            $this->divmod($temp, $b, $bn, $a, $an);
            $bn = $this->numsize($b, $bn);

            if ($bn === 0) {
                return $x;
            }
            $this->mula32($y, $x, $temp, $qn, -1);

            $qn = $an - $bn + 1;
            $this->divmod($temp, $a, $an, $b, $bn);
            $an = $this->numsize($a, $an);

            if ($an === 0) {
                return $y;
            }
            $this->mula32($x, $y, $temp, $qn, -1);
        }
    }

    public function unpack(&$x, &$m)
    {
        for ($i = 0; $i < $this->KEY_SIZE; $i += 2) {
            $x[$i / 2] = $m[$i] & 0xFF | (($m[$i + 1] & 0xFF) << 8);
        }
    }

    public function is_overflow($x)
    {
        return (
                        (($x[0] > $this->P26 - 19)) &&
                                (($x[1] & $x[3] & $x[5] & $x[7] & $x[9]) === $this->P25) &&
                                (($x[2] & $x[4] & $x[6] & $x[8]) === $this->P26)
                        ) || ($x[9] > $this->P25);
    }

    public function pack(&$x, &$m)
    {
        for ($i = 0; $i < $this->UNPACKED_SIZE; ++$i) {
            $m[2 * $i] = $x[$i] & 0x00FF;
            $m[2 * $i + 1] = ($x[$i] & 0xFF00) >> 8;
        }
    }

    public function createUnpackedArray()
    {
        return array_pad(array(), 16, 0);
    }

    public function cpy(&$d, &$s)
    {
        for ($i = 0; $i < $this->UNPACKED_SIZE; ++$i) {
            $d[$i] = $s[$i];
        }
    }

    public function set(&$d, $s)
    {
        $d[0] = $s;
        for ($i = 1; $i < $this->UNPACKED_SIZE; ++$i) {
            $d[$i] = 0;
        }
    }

    public function recip(&$y, &$x, $sqrtassist)
    {
        $t0 = $this->createUnpackedArray();
        $t1 = $this->createUnpackedArray();
        $t2 = $this->createUnpackedArray();
        $t3 = $this->createUnpackedArray();
        $t4 = $this->createUnpackedArray();

        $i;
        $this->sqr($t1, $x);
        $this->sqr($t2, $t1);
        $this->sqr($t0, $t2);
        $this->mul($t2, $t0, $x);
        $this->mul($t0, $t2, $t1);
        $this->sqr($t1, $t0);
        $this->mul($t3, $t1, $t2);
        $this->sqr($t1, $t3);
        $this->sqr($t2, $t1);
        $this->sqr($t1, $t2);
        $this->sqr($t2, $t1);
        $this->sqr($t1, $t2);
        $this->mul($t2, $t1, $t3);
        $this->sqr($t1, $t2);
        $this->sqr($t3, $t1);
        for ($i = 1; $i < 5; $i++) {
            $this->sqr($t1, $t3);
            $this->sqr($t3, $t1);
        }
        $this->mul($t1, $t3, $t2);
        $this->sqr($t3, $t1);
        $this->sqr($t4, $t3);
        for ($i = 1; $i < 10; $i++) {
            $this->sqr($t3, $t4);
            $this->sqr($t4, $t3);
        }
        $this->mul($t3, $t4, $t1);
        for ($i = 0; $i < 5; $i++) {
            $this->sqr($t1, $t3);
            $this->sqr($t3, $t1);
        }
        $this->mul($t1, $t3, $t2);
        $this->sqr($t2, $t1);
        $this->sqr($t3, $t2);
        for ($i = 1; $i < 25; $i++) {
            $this->sqr($t2, $t3);
            $this->sqr($t3, $t2);
        }
        $this->mul($t2, $t3, $t1);
        $this->sqr($t3, $t2);
        $this->sqr($t4, $t3);
        for ($i = 1; $i < 50; $i++) {
            $this->sqr($t3, $t4);
            $this->sqr($t4, $t3);
        }
        $this->mul($t3, $t4, $t2);
        for ($i = 0; $i < 25; $i++) {
            $this->sqr($t4, $t3);
            $this->sqr($t3, $t4);
        }
        $this->mul($t2, $t3, $t1);
        $this->sqr($t1, $t2);
        $this->sqr($t2, $t1);
        if ($sqrtassist != 0) {
            $this->mul($y, $x, $t2);
        } else {
            $this->sqr($t1, $t2);
            $this->sqr($t2, $t1);
            $this->sqr($t1, $t2);
            $this->mul($y, $t1, $t0);
        }
    }

    public function is_negative(&$x)
    {
        $isOverflowOrNegative = $this->is_overflow($x) || $x[9] < 0;
        $leastSignificantBit = $x[0] & 1;
        return (($isOverflowOrNegative ? 1 : 0) ^ $leastSignificantBit) & 0xFFFFFFFF;
    }

    public function sqrt(&$x, &$u)
    {
        $v = $this->createUnpackedArray();
        $t1 = $this->createUnpackedArray();
        $t2 = $this->createUnpackedArray();

        $this->add($t1, $u, $u);
        $this->recip($v, $t1, 1);
        $this->sqr($x, $v);
        $this->mul($t2, $t1, $x);
        $this->sub($t2, $t2, $this->C1);
        $this->mul($t1, $v, $t2);
        $this->mul($x, $u, $t1);
    }

    public function c255lsqr8h($a7, $a6, $a5, $a4, $a3, $a2, $a1, $a0)
    {
        $r = array_pad(array(), 16, 0);
        $v;
        $r[0] = ($v = $a0*$a0) & 0xFFFF;
        $r[1] = ($v = (($v / 0x10000) | 0) + 2*$a0*$a1) & 0xFFFF;
        $r[2] = ($v = (($v / 0x10000) | 0) + 2*$a0*$a2 + $a1*$a1) & 0xFFFF;
        $r[3] = ($v = (($v / 0x10000) | 0) + 2*$a0*$a3 + 2*$a1*$a2) & 0xFFFF;
        $r[4] = ($v = (($v / 0x10000) | 0) + 2*$a0*$a4 + 2*$a1*$a3 + $a2*$a2) & 0xFFFF;
        $r[5] = ($v = (($v / 0x10000) | 0) + 2*$a0*$a5 + 2*$a1*$a4 + 2*$a2*$a3) & 0xFFFF;
        $r[6] = ($v = (($v / 0x10000) | 0) + 2*$a0*$a6 + 2*$a1*$a5 + 2*$a2*$a4 + $a3*$a3) & 0xFFFF;
        $r[7] = ($v = (($v / 0x10000) | 0) + 2*$a0*$a7 + 2*$a1*$a6 + 2*$a2*$a5 + 2*$a3*$a4) & 0xFFFF;
        $r[8] = ($v = (($v / 0x10000) | 0) + 2*$a1*$a7 + 2*$a2*$a6 + 2*$a3*$a5 + $a4*$a4) & 0xFFFF;
        $r[9] = ($v = (($v / 0x10000) | 0) + 2*$a2*$a7 + 2*$a3*$a6 + 2*$a4*$a5) & 0xFFFF;
        $r[10] = ($v = (($v / 0x10000) | 0) + 2*$a3*$a7 + 2*$a4*$a6 + $a5*$a5) & 0xFFFF;
        $r[11] = ($v = (($v / 0x10000) | 0) + 2*$a4*$a7 + 2*$a5*$a6) & 0xFFFF;
        $r[12] = ($v = (($v / 0x10000) | 0) + 2*$a5*$a7 + $a6*$a6) & 0xFFFF;
        $r[13] = ($v = (($v / 0x10000) | 0) + 2*$a6*$a7) & 0xFFFF;
        $r[14] = ($v = (($v / 0x10000) | 0) + $a7*$a7) & 0xFFFF;
        $r[15] = (($v / 0x10000) | 0);
        return $r;
    }

    public function sqr(&$r, &$a)
    {
        $x = $this->c255lsqr8h($a[15], $a[14], $a[13], $a[12], $a[11], $a[10], $a[9], $a[8]);
        $z = $this->c255lsqr8h($a[7], $a[6], $a[5], $a[4], $a[3], $a[2], $a[1], $a[0]);
        $y = $this->c255lsqr8h($a[15] + $a[7], $a[14] + $a[6], $a[13] + $a[5], $a[12] + $a[4], $a[11] + $a[3], $a[10] + $a[2], $a[9] + $a[1], $a[8] + $a[0]);
        $v;
        $v = 0x800000 + $z[0] + ($y[8] -$x[8] -$z[8] + $x[0] -0x80) * 38;
        $r[0] = $v & 0xFFFF;
        $v = 0x7fff80 + (($v / 0x10000) | 0) + $z[1] + ($y[9] -$x[9] -$z[9] + $x[1]) * 38;
        $r[1] = $v & 0xFFFF;
        $v = 0x7fff80 + (($v / 0x10000) | 0) + $z[2] + ($y[10] -$x[10] -$z[10] + $x[2]) * 38;
        $r[2] = $v & 0xFFFF;
        $v = 0x7fff80 + (($v / 0x10000) | 0) + $z[3] + ($y[11] -$x[11] -$z[11] + $x[3]) * 38;
        $r[3] = $v & 0xFFFF;
        $v = 0x7fff80 + (($v / 0x10000) | 0) + $z[4] + ($y[12] -$x[12] -$z[12] + $x[4]) * 38;
        $r[4] = $v & 0xFFFF;
        $v = 0x7fff80 + (($v / 0x10000) | 0) + $z[5] + ($y[13] -$x[13] -$z[13] + $x[5]) * 38;
        $r[5] = $v & 0xFFFF;
        $v = 0x7fff80 + (($v / 0x10000) | 0) + $z[6] + ($y[14] -$x[14] -$z[14] + $x[6]) * 38;
        $r[6] = $v & 0xFFFF;
        $v = 0x7fff80 + (($v / 0x10000) | 0) + $z[7] + ($y[15] -$x[15] -$z[15] + $x[7]) * 38;
        $r[7] = $v & 0xFFFF;
        $v = 0x7fff80 + (($v / 0x10000) | 0) + $z[8] + $y[0] -$x[0] -$z[0] + $x[8] * 38;
        $r[8] = $v & 0xFFFF;
        $v = 0x7fff80 + (($v / 0x10000) | 0) + $z[9] + $y[1] -$x[1] -$z[1] + $x[9] * 38;
        $r[9] = $v & 0xFFFF;
        $v = 0x7fff80 + (($v / 0x10000) | 0) + $z[10] + $y[2] -$x[2] -$z[2] + $x[10] * 38;
        $r[10] = $v & 0xFFFF;
        $v = 0x7fff80 + (($v / 0x10000) | 0) + $z[11] + $y[3] -$x[3] -$z[3] + $x[11] * 38;
        $r[11] = $v & 0xFFFF;
        $v = 0x7fff80 + (($v / 0x10000) | 0) + $z[12] + $y[4] -$x[4] -$z[4] + $x[12] * 38;
        $r[12] = $v & 0xFFFF;
        $v = 0x7fff80 + (($v / 0x10000) | 0) + $z[13] + $y[5] -$x[5] -$z[5] + $x[13] * 38;
        $r[13] = $v & 0xFFFF;
        $v = 0x7fff80 + (($v / 0x10000) | 0) + $z[14] + $y[6] -$x[6] -$z[6] + $x[14] * 38;
        $r[14] = $v & 0xFFFF;
        $r15 = 0x7fff80 + (($v / 0x10000) | 0) + $z[15] + $y[7] -$x[7] -$z[7] + $x[15] * 38;
        $this->c255lreduce($r, $r15);
    }

    public function c255lmul8h($a7, $a6, $a5, $a4, $a3, $a2, $a1, $a0, $b7, $b6, $b5, $b4, $b3, $b2, $b1, $b0)
    {
        $r = array_pad(array(), 16, 0);
        $v;
        $r[0] = ($v = $a0*$b0) & 0xFFFF;
        $r[1] = ($v = (($v / 0x10000) | 0) + $a0*$b1 + $a1*$b0) & 0xFFFF;
        $r[2] = ($v = (($v / 0x10000) | 0) + $a0*$b2 + $a1*$b1 + $a2*$b0) & 0xFFFF;
        $r[3] = ($v = (($v / 0x10000) | 0) + $a0*$b3 + $a1*$b2 + $a2*$b1 + $a3*$b0) & 0xFFFF;
        $r[4] = ($v = (($v / 0x10000) | 0) + $a0*$b4 + $a1*$b3 + $a2*$b2 + $a3*$b1 + $a4*$b0) & 0xFFFF;
        $r[5] = ($v = (($v / 0x10000) | 0) + $a0*$b5 + $a1*$b4 + $a2*$b3 + $a3*$b2 + $a4*$b1 + $a5*$b0) & 0xFFFF;
        $r[6] = ($v = (($v / 0x10000) | 0) + $a0*$b6 + $a1*$b5 + $a2*$b4 + $a3*$b3 + $a4*$b2 + $a5*$b1 + $a6*$b0) & 0xFFFF;
        $r[7] = ($v = (($v / 0x10000) | 0) + $a0*$b7 + $a1*$b6 + $a2*$b5 + $a3*$b4 + $a4*$b3 + $a5*$b2 + $a6*$b1 + $a7*$b0) & 0xFFFF;
        $r[8] = ($v = (($v / 0x10000) | 0) + $a1*$b7 + $a2*$b6 + $a3*$b5 + $a4*$b4 + $a5*$b3 + $a6*$b2 + $a7*$b1) & 0xFFFF;
        $r[9] = ($v = (($v / 0x10000) | 0) + $a2*$b7 + $a3*$b6 + $a4*$b5 + $a5*$b4 + $a6*$b3 + $a7*$b2) & 0xFFFF;
        $r[10] = ($v = (($v / 0x10000) | 0) + $a3*$b7 + $a4*$b6 + $a5*$b5 + $a6*$b4 + $a7*$b3) & 0xFFFF;
        $r[11] = ($v = (($v / 0x10000) | 0) + $a4*$b7 + $a5*$b6 + $a6*$b5 + $a7*$b4) & 0xFFFF;
        $r[12] = ($v = (($v / 0x10000) | 0) + $a5*$b7 + $a6*$b6 + $a7*$b5) & 0xFFFF;
        $r[13] = ($v = (($v / 0x10000) | 0) + $a6*$b7 + $a7*$b6) & 0xFFFF;
        $r[14] = ($v = (($v / 0x10000) | 0) + $a7*$b7) & 0xFFFF;
        $r[15] = (($v / 0x10000) | 0);
        return $r;
    }

    public function mul(&$r, &$a, &$b)
    {
        $x = $this->c255lmul8h($a[15], $a[14], $a[13], $a[12], $a[11], $a[10], $a[9], $a[8], $b[15], $b[14], $b[13], $b[12], $b[11], $b[10], $b[9], $b[8]);
        $z = $this->c255lmul8h($a[7], $a[6], $a[5], $a[4], $a[3], $a[2], $a[1], $a[0], $b[7], $b[6], $b[5], $b[4], $b[3], $b[2], $b[1], $b[0]);
        $y = $this->c255lmul8h(
                    $a[15] + $a[7],
                    $a[14] + $a[6],
                    $a[13] + $a[5],
                    $a[12] + $a[4],
                    $a[11] + $a[3],
                    $a[10] + $a[2],
                    $a[9] + $a[1],
                    $a[8] + $a[0],
                    $b[15] + $b[7],
                    $b[14] + $b[6],
                    $b[13] + $b[5],
                    $b[12] + $b[4],
                    $b[11] + $b[3],
                    $b[10] + $b[2],
                    $b[9] + $b[1],
                    $b[8] + $b[0]
                );

        $v;
        $r[0] = ($v = 0x800000 + $z[0] + ($y[8] -$x[8] -$z[8] + $x[0] -0x80) * 38) & 0xFFFF;
        $r[1] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[1] + ($y[9] -$x[9] -$z[9] + $x[1]) * 38) & 0xFFFF;
        $r[2] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[2] + ($y[10] -$x[10] -$z[10] + $x[2]) * 38) & 0xFFFF;
        $r[3] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[3] + ($y[11] -$x[11] -$z[11] + $x[3]) * 38) & 0xFFFF;
        $r[4] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[4] + ($y[12] -$x[12] -$z[12] + $x[4]) * 38) & 0xFFFF;
        $r[5] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[5] + ($y[13] -$x[13] -$z[13] + $x[5]) * 38) & 0xFFFF;
        $r[6] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[6] + ($y[14] -$x[14] -$z[14] + $x[6]) * 38) & 0xFFFF;
        $r[7] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[7] + ($y[15] -$x[15] -$z[15] + $x[7]) * 38) & 0xFFFF;
        $r[8] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[8] + $y[0] -$x[0] -$z[0] + $x[8] * 38) & 0xFFFF;
        $r[9] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[9] + $y[1] -$x[1] -$z[1] + $x[9] * 38) & 0xFFFF;
        $r[10] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[10] + $y[2] -$x[2] -$z[2] + $x[10] * 38) & 0xFFFF;
        $r[11] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[11] + $y[3] -$x[3] -$z[3] + $x[11] * 38) & 0xFFFF;
        $r[12] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[12] + $y[4] -$x[4] -$z[4] + $x[12] * 38) & 0xFFFF;
        $r[13] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[13] + $y[5] -$x[5] -$z[5] + $x[13] * 38) & 0xFFFF;
        $r[14] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[14] + $y[6] -$x[6] -$z[6] + $x[14] * 38) & 0xFFFF;
        $r15 = 0x7fff80 + (($v / 0x10000) | 0) + $z[15] + $y[7] -$x[7] -$z[7] + $x[15] * 38;
        $this->c255lreduce($r, $r15);
    }


    public function c255lreduce(&$a, &$a15)
    {
        $v = $a15;
        $a[15] = $v & 0x7FFF;
        $v = (($v / 0x8000) | 0) * 19;
        for ($i = 0; $i <= 14; ++$i) {
            $v += $a[$i];
            $a[$i] = $v & 0xFFFF;
            $v = (($v / 0x10000) | 0);
        }

        $a[15] += $v;
    }

    public function add(&$r, &$a, &$b)
    {
        $v;
        $r[0] = ($v = ((($a[15] / 0x8000) | 0) + (($b[15] / 0x8000) | 0)) * 19 + $a[0] + $b[0]) & 0xFFFF;
        for ($i = 1; $i <= 14; ++$i) {
            $r[$i] = ($v = (($v / 0x10000) | 0) + $a[$i] + $b[$i]) & 0xFFFF;
        }
        $r[15] = (($v / 0x10000) | 0) + ($a[15] & 0x7FFF) + ($b[15] & 0x7FFF);
    }

    public function sub(&$r, &$a, &$b)
    {
        $v;
        $r[0] = ($v = 0x80000 + ((($a[15] / 0x8000) | 0) - (($b[15] / 0x8000) | 0) - 1) * 19 + $a[0] - $b[0]) & 0xFFFF;
        for ($i = 1; $i <= 14; ++$i) {
            $r[$i] = ($v = (($v / 0x10000) | 0) + 0x7fff8 + $a[$i] - $b[$i]) & 0xFFFF;
        }
        $r[15] = (($v / 0x10000) | 0) + 0x7ff8 + ($a[15] & 0x7FFF) - ($b[15] & 0x7FFF);
    }

    public function mul_small(&$r, &$a, $m)
    {
        $v;
        $r[0] = ($v = $a[0] * $m) & 0xFFFF;
        for ($i = 1; $i <= 14; ++$i) {
            $r[$i] = ($v = (($v / 0x10000) | 0) + $a[$i]*$m) & 0xFFFF;
        }
        $r15 = (($v / 0x10000) | 0) + $a[15]*$m;
        $this->c255lreduce($r, $r15);
    }

    public function mont_prep(&$t1, &$t2, &$ax, &$az)
    {
        $this->add($t1, $ax, $az);
        $this->sub($t2, $ax, $az);
    }

    public function mont_add(&$t1, &$t2, &$t3, &$t4, &$ax, &$az, &$dx)
    {
        $this->mul($ax, $t2, $t3);
        $this->mul($az, $t1, $t4);
        $this->add($t1, $ax, $az);
        $this->sub($t2, $ax, $az);
        $this->sqr($ax, $t1);
        $this->sqr($t1, $t2);
        $this->mul($az, $t1, $dx);
    }

    public function mont_dbl(&$t1, &$t2, &$t3, &$t4, &$bx, &$bz)
    {
        $this->sqr($t1, $t3);
        $this->sqr($t2, $t4);
        $this->mul($bx, $t1, $t2);
        $this->sub($t2, $t1, $t2);
        $this->mul_small($bz, $t2, 121665);
        $this->add($t1, $t1, $bz);
        $this->mul($bz, $t1, $t2);
    }

    public function x_to_y2(&$t, &$y2, &$x)
    {
        $this->sqr($t, $x);
        $this->mul_small($y2, $x, 486662);
        $this->add($t, $t, $y2);
        $this->add($t, $t, $this->C1);
        $this->mul($y2, $t, $x);
    }

    public function modval(&$a, $modto)
    {
        for ($i=0;$i<count($a);$i++) {
            $a[$i] = $a[$i] % $modto;
        }
    }

    public function core(&$Px, &$s, &$k, $Gx)
    {
        $dx = $this->createUnpackedArray();
        $t1 = $this->createUnpackedArray();
        $t2 = $this->createUnpackedArray();
        $t3 = $this->createUnpackedArray();
        $t4 = $this->createUnpackedArray();
        $x = [$this->createUnpackedArray(), $this->createUnpackedArray()];
        $z = [$this->createUnpackedArray(), $this->createUnpackedArray()];
        $i;
        $j;

        if (isset($Gx)) {
            $this->unpack($dx, $Gx);
        } else {
            $this->set($dx, 9);
        }

        $this->set($x[0], 1);
        $this->set($z[0], 0);

        $this->cpy($x[1], $dx);
        $this->set($z[1], 1);

        for ($i = 32; $i-- !== 0;) {
            for ($j = 8; $j-- !== 0;) {
                $bit1 = ($k[$i] & 0xFF) >> $j & 1;
                if ($bit1 == 0) {
                    $bit0 = 1;
                } else {
                    $bit0 = 0;
                }
                $ax = $x[$bit0];
                $az = $z[$bit0];
                $bx = $x[$bit1];
                $bz = $z[$bit1];
                $this->mont_prep($t1, $t2, $ax, $az);
                $this->mont_prep($t3, $t4, $bx, $bz);
                $this->mont_add($t1, $t2, $t3, $t4, $ax, $az, $dx);
                $this->mont_dbl($t1, $t2, $t3, $t4, $bx, $bz);
                $x[$bit0] = $ax;
                $z[$bit0] = $az;
                $x[$bit1] = $bx;
                $z[$bit1] = $bz;
            }
        }

        $this->recip($t1, $z[0], 0);
        $this->mul($dx, $x[0], $t1);
        $this->pack($dx, $Px);

        if ($s !== null) {
            $this->x_to_y2($t2, $t1, $dx);
            $this->recip($t3, $z[1], 0);
            $this->mul($t2, $x[1], $t3);
            $this->add($t2, $t2, $dx);
            $this->add($t2, $t2, $this->C486671);
            $this->sub($dx, $dx, $this->C9);
            $this->sqr($t3, $dx);
            $this->mul($dx, $t2, $t3);
            $this->sub($dx, $dx, $t1);
            $this->sub($dx, $dx, $this->C39420360);
            $this->mul($t1, $dx, $this->BASE_R2Y);


            if ($this->is_negative($t1) !== 0) {
                $this->cpy32($s, $k);
            } else {
                $this->mula_small($s, $this->ORDER_TIMES_8, 0, $k, 32, -1);
            }

            $temp1 = array_pad(array(), 32, 0);
            $temp2 = array_pad(array(), 64, 0);
            $temp3 = array_pad(array(), 64, 0);
            $this->cpy32($temp1, $this->ORDER);
            $this->cpy32($s, $this->egcd32($temp2, $temp3, $s, $temp1));

            if (($s[31] & 0x80) !== 0) {
                $this->mula_small($s, $s, 0, $this->ORDER, 32, 1);
            }
        }
    }

    public function sign($h, $x, $s)
    {
        $w;
        $i;
        $h1 = array_pad(array(), 32, 0);
        $x1 = array_pad(array(), 32, 0);
        $tmp1 = array_pad(array(), 64, 0);
        $tmp2 = array_pad(array(), 64, 0);

        $this->cpy32($h1, $h);
        $this->cpy32($x1, $x);

        $tmp3 = array_pad(array(), 32, 0);
        $this->divmod($tmp3, $h1, 32, $this->ORDER, 32);
        $this->divmod($tmp3, $x1, 32, $this->ORDER, 32);

        $v = array_pad(array(), 32, 0);
        $this->mula_small($v, $x1, 0, $h1, 32, -1);
        $this->mula_small($v, $v, 0, $this->ORDER, 32, 1);

        $this->mula32($tmp1, $v, $s, 32, 1);
        $this->divmod($tmp2, $tmp1, 64, $this->ORDER, 32);

        for ($w = 0, $i = 0; $i < 32; $i++) {
            $v[$i] = $tmp1[$i];
            $w =  $w | $v[$i];
        }

        return $w !== 0 ? $v : undefined;
    }

    public function verify($v, $h, $P)
    {
        $d = array();
        $p = [$this->createUnpackedArray(), $this->createUnpackedArray()];
        $s = [$this->createUnpackedArray(), $this->createUnpackedArray()];
        $yx = [$this->createUnpackedArray(), $this->createUnpackedArray(), $this->createUnpackedArray()];
        $yz = [$this->createUnpackedArray(), $this->createUnpackedArray(), $this->createUnpackedArray()];
        $t1 = [$this->createUnpackedArray(), $this->createUnpackedArray(), $this->createUnpackedArray()];
        $t2 = [$this->createUnpackedArray(), $this->createUnpackedArray(), $this->createUnpackedArray()];

        $vi = 0;
        $hi = 0;
        $di = 0;
        $nvh = 0;
        $i;
        $j;
        $k;

        $this->set($p[0], 9);
        $this->unpack($p[1], $P);

        $this->x_to_y2($t1[0], $t2[0], $p[1]);
        $this->sqrt($t1[0], $t2[0]);

        $j = $this->is_negative($t1[0]);
        $this->add($t2[0], $t2[0], $this->C39420360);
        $this->mul($t2[1], $this->BASE_2Y, $t1[0]);
        $this->sub($t1[$j], $t2[0], $t2[1]);
        $this->add($t1[1 - $j], $t2[0], $t2[1]);
        $this->cpy($t2[0], $p[1]);
        $this->sub($t2[0], $t2[0], $this->C9);
        $this->sqr($t2[1], $t2[0]);
        $this->recip($t2[0], $t2[1], 0);
        $this->mul($s[0], $t1[0], $t2[0]);

        $this->sub($s[0], $s[0], $p[1]);
        $this->sub($s[0], $s[0], $this->C486671);
        $this->mul($s[1], $t1[1], $t2[0]);
        $this->sub($s[1], $s[1], $p[1]);
        $this->sub($s[1], $s[1], $this->C486671);

        $this->mul_small($s[0], $s[0], 1);
        $this-> mul_small($s[1], $s[1], 1);

        for ($i = 0; $i < 32; $i++) {
            $vi = ($vi >> 8) ^ ($v[$i] & 0xFF) ^ (($v[$i] & 0xFF) << 1);
            $hi = ($hi >> 8) ^ ($h[$i] & 0xFF) ^ (($h[$i] & 0xFF) << 1);
            $nvh = ~($vi ^ $hi);
            $di = ($nvh & ($di & 0x80) >> 7) ^ $vi;
            $di ^= $nvh & ($di & 0x01) << 1;
            $di ^= $nvh & ($di & 0x02) << 1;
            $di ^= $nvh & ($di & 0x04) << 1;
            $di ^= $nvh & ($di & 0x08) << 1;
            $di ^= $nvh & ($di & 0x10) << 1;
            $di ^= $nvh & ($di & 0x20) << 1;
            $di ^= $nvh & ($di & 0x40) << 1;
            $d[$i] = $di & 0xFF;
        }

        $di = (($nvh & ($di & 0x80) << 1) ^ $vi) >> 8;
        $this->set($yx[0], 1);
        $this->cpy($yx[1], $p[$di]);
        $this->cpy($yx[2], $s[0]);
        $this->set($yz[0], 0);
        $this->set($yz[1], 1);
        $this->set($yz[2], 1);
        $vi = 0;
        $hi = 0;

        for ($i = 32; $i-- !== 0;) {
            $vi = ($vi << 8) | ($v[$i] & 0xFF);
            $hi = ($hi << 8) | ($h[$i] & 0xFF);
            $di = ($di << 8) | ($d[$i] & 0xFF);

            for ($j = 8; $j-- !== 0;) {
                $this->mont_prep($t1[0], $t2[0], $yx[0], $yz[0]);
                $this->mont_prep($t1[1], $t2[1], $yx[1], $yz[1]);
                $this->mont_prep($t1[2], $t2[2], $yx[2], $yz[2]);

                $k = (($vi ^ $vi >> 1) >> $j & 1)
                                        + (($hi ^ $hi >> 1) >> $j & 1);
                $this->mont_dbl($yx[2], $yz[2], $t1[$k], $t2[$k], $yx[0], $yz[0]);

                $k = ($di >> $j & 2) ^ (($di >> $j & 1) << 1);
                $this->mont_add(
                                    $t1[1],
                                    $t2[1],
                                    $t1[$k],
                                    $t2[$k],
                                    $yx[1],
                                    $yz[1],
                                    $p[$di >> $j & 1]
                                );

                $this->mont_add(
                                    $t1[2],
                                    $t2[2],
                                    $t1[0],
                                    $t2[0],
                                    $yx[2],
                                    $yz[2],
                                    $s[(($vi ^ $hi) >> $j & 2) >> 1]
                                );
            }
        }

        $k = ($vi & 1) + ($hi & 1);
        $this->recip($t1[0], $yz[$k], 0);
        $this->mul($t1[1], $yx[$k], $t1[0]);
        $Y = array();
        $this->pack($t1[1], $Y);
        return $Y;
    }

    public function keygen(&$k)
    {
        $P = array_pad(array(), 32, 0);
        $s = array_pad(array(), 32, 0);
        $k = $this->clamp($k);
        $this->core($P, $s, $k, null);
        $obj = new STDClass();
        $obj->p = $P;
        $obj->s = $s;
        $obj->k = $k;
        return $obj;
    }
}
