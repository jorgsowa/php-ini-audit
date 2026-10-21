<?php

namespace PhpIniAudit;

final class Finding
{
    public string $ruleId;
    public string $title;
    public string $category;
    public int $severity;
    public int $confidence;
    public string $message;
    public string $recommendation;
    public string $target;
    public ?string $directive = null;
    public ?string $value = null;
    public ?Location $location = null;
    public bool $fromDefault = false;
    public ?string $cwe = null;
    /** @var list<string> */
    public array $references = [];

    public function __construct(string $ruleId, string $title, string $category, int $severity, int $confidence,
        string $message, string $recommendation, string $target)
    {
        $this->ruleId = $ruleId;
        $this->title = $title;
        $this->category = $category;
        $this->severity = $severity;
        $this->confidence = $confidence;
        $this->message = $message;
        $this->recommendation = $recommendation;
        $this->target = $target;
    }

    public function toArray(): array
    {
        return [
            'rule_id' => $this->ruleId,
            'title' => $this->title,
            'category' => $this->category,
            'severity' => Severity::name($this->severity),
            'confidence' => Confidence::name($this->confidence),
            'message' => $this->message,
            'recommendation' => $this->recommendation,
            'target' => $this->target,
            'directive' => $this->directive,
            'value' => $this->value,
            'file' => $this->location ? $this->location->path : null,
            'line' => $this->location ? $this->location->line : null,
            'from_default' => $this->fromDefault,
            'cwe' => $this->cwe,
            'references' => $this->references,
        ];
    }
}
