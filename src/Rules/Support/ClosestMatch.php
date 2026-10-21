<?php

namespace PhpIniAudit\Rules\Support;

/** difflib.get_close_matches() with n = 1: the most similar word by Ratcliff/Obershelp ratio. */
final class ClosestMatch
{
    /** The most similar candidate by Ratcliff/Obershelp ratio at or above $cutoff, or null. */
    public static function find(string $word, array $possibilities, float $cutoff): ?string
    {
        $b = self::chars($word);
        $lb = count($b);
        $b2j = [];
        foreach ($b as $j => $char) {
            $b2j[$char][] = $j;
        }
        $best = null;
        $bestScore = -1.0;
        foreach ($possibilities as $candidate) {
            $a = self::chars($candidate);
            $la = count($a);
            $total = $la + $lb;
            // real_quick_ratio(): an upper bound that skips most candidates cheaply.
            if (($total ? 2.0 * min($la, $lb) / $total : 1.0) < $cutoff) {
                continue;
            }
            $score = $total ? 2.0 * self::matchingCharacters($a, $b2j, $la, $lb) / $total : 1.0;
            if ($score < $cutoff) {
                continue;
            }
            if ($score > $bestScore || ($score === $bestScore && strcmp($candidate, (string) $best) > 0)) {
                $best = $candidate;
                $bestScore = $score;
            }
        }
        return $best;
    }

    /** @return list<string> */
    private static function chars(string $text): array
    {
        $chars = preg_split('//u', $text, -1, PREG_SPLIT_NO_EMPTY);
        return $chars === false ? str_split($text) : $chars;
    }

    /** Total size of SequenceMatcher.get_matching_blocks() for a junk-free sequence pair. */
    private static function matchingCharacters(array $a, array $b2j, int $la, int $lb): int
    {
        $queue = [[0, $la, 0, $lb]];
        $matches = 0;
        while ($queue) {
            [$alo, $ahi, $blo, $bhi] = array_pop($queue);
            $besti = $alo;
            $bestj = $blo;
            $bestsize = 0;
            $j2len = [];
            for ($i = $alo; $i < $ahi; $i++) {
                $newj2len = [];
                foreach ($b2j[$a[$i]] ?? [] as $j) {
                    if ($j < $blo) {
                        continue;
                    }
                    if ($j >= $bhi) {
                        break;
                    }
                    $k = $newj2len[$j] = ($j2len[$j - 1] ?? 0) + 1;
                    if ($k > $bestsize) {
                        $besti = $i - $k + 1;
                        $bestj = $j - $k + 1;
                        $bestsize = $k;
                    }
                }
                $j2len = $newj2len;
            }
            if ($bestsize) {
                $matches += $bestsize;
                if ($alo < $besti && $blo < $bestj) {
                    $queue[] = [$alo, $besti, $blo, $bestj];
                }
                if ($besti + $bestsize < $ahi && $bestj + $bestsize < $bhi) {
                    $queue[] = [$besti + $bestsize, $ahi, $bestj + $bestsize, $bhi];
                }
            }
        }
        return $matches;
    }
}
